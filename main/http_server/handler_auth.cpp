#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"

#include "ArduinoJson.h"

#include "psram_allocator.h"
#include "global_state.h"
#include "nvs_config.h"
#include "http_cors.h"
#include "http_utils.h"
#include "handler_auth.h"

#include <string.h>
#include <time.h>

static const char *TAG = "http_auth";

// Simple in-memory session storage (replace with persistent storage if needed)
static char current_session_token[65] = {0};  // 64 char token + null terminator
static time_t session_expiry = 0;

// Default credentials (should be configurable via NVS)
static const char* DEFAULT_USERNAME = "admin";
static const char* DEFAULT_PASSWORD = "bitaxe";  // Change this!

// Generate a random session token
static void generate_session_token(char* token, size_t token_size) {
    const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (size_t i = 0; i < token_size - 1; i++) {
        token[i] = charset[esp_random() % (sizeof(charset) - 1)];
    }
    token[token_size - 1] = '\0';
}

// Validate session token
static bool is_valid_session(const char* token) {
    if (!token || strlen(token) == 0) {
        return false;
    }
    
    time_t now = time(NULL);
    if (now > session_expiry) {
        // Session expired
        memset(current_session_token, 0, sizeof(current_session_token));
        return false;
    }
    
    return strcmp(current_session_token, token) == 0;
}

// Extract token from Authorization header
static bool extract_bearer_token(httpd_req_t *req, char* token, size_t token_size) {
    char auth_header[256];
    size_t auth_len = httpd_req_get_hdr_value_len(req, "Authorization");
    
    if (auth_len == 0 || auth_len >= sizeof(auth_header)) {
        return false;
    }
    
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth_header, sizeof(auth_header)) != ESP_OK) {
        return false;
    }
    
    // Check for "Bearer " prefix
    if (strncmp(auth_header, "Bearer ", 7) != 0) {
        return false;
    }
    
    strncpy(token, auth_header + 7, token_size - 1);
    token[token_size - 1] = '\0';
    return true;
}

/* Authentication middleware - check if request is authenticated */
bool is_authenticated(httpd_req_t *req) {
    char token[65];
    if (!extract_bearer_token(req, token, sizeof(token))) {
        return false;
    }
    
    return is_valid_session(token);
}

/* Sign-in endpoint */
esp_err_t POST_auth_signin(httpd_req_t *req) {
    if (is_network_allowed(req) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
    }

    httpd_resp_set_type(req, "application/json");
    
    // Set CORS headers
    if (set_cors_headers(req) != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    // Get request body
    char *buf = (char*)malloc(req->content_len + 1);
    if (!buf) {
        ESP_LOGE(TAG, "No memory for request body");
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    int ret = httpd_req_recv(req, buf, req->content_len);
    if (ret <= 0) {
        free(buf);
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        } else {
            httpd_resp_send_500(req);
        }
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    // Parse JSON request
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, buf);
    free(buf);

    if (error) {
        ESP_LOGE(TAG, "JSON parse error: %s", error.c_str());
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    // Extract credentials
    const char* email = doc["email"];
    const char* password = doc["password"];

    if (!email || !password) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing email or password");
        return ESP_FAIL;
    }

    // Validate credentials (simple check - in production use proper password hashing)
    if (strcmp(email, DEFAULT_USERNAME) == 0 && strcmp(password, DEFAULT_PASSWORD) == 0) {
        // Generate session token
        generate_session_token(current_session_token, sizeof(current_session_token));
        
        // Set expiry to 24 hours from now
        session_expiry = time(NULL) + (24 * 60 * 60);
        
        // Create response
        JsonDocument response;
        response["success"] = true;
        response["data"]["redirect"] = "/pages";
        response["data"]["token"] = current_session_token;
        response["data"]["expires"] = session_expiry;
        response["messages"] = JsonArray();
        
        ESP_LOGI(TAG, "User authenticated successfully");
        esp_err_t ret = sendJsonResponse(req, response);
        return ret;
        return ESP_OK;
    } else {
        // Invalid credentials
        JsonDocument response;
        response["success"] = false;
        response["errors"] = JsonArray();
        response["errors"][0] = "Invalid email or password";
        
        ESP_LOGW(TAG, "Authentication failed for user: %s", email);
        httpd_resp_set_status(req, "401 Unauthorized");
        esp_err_t ret = sendJsonResponse(req, response);
        return ret;
        return ESP_OK;
    }
}

/* Sign-out endpoint */
esp_err_t POST_auth_signout(httpd_req_t *req) {
    if (is_network_allowed(req) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
    }

    httpd_resp_set_type(req, "application/json");
    
    // Set CORS headers
    if (set_cors_headers(req) != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    // Clear session token
    memset(current_session_token, 0, sizeof(current_session_token));
    session_expiry = 0;
    
    // Create response
    JsonDocument response;
    response["success"] = true;
    response["messages"] = JsonArray();
    response["messages"][0] = "Successfully logged out";
    
    ESP_LOGI(TAG, "User signed out");
    esp_err_t ret = sendJsonResponse(req, response);
    return ret;
    return ESP_OK;
}

/* Request password reset endpoint */
esp_err_t POST_auth_request_pass(httpd_req_t *req) {
    if (is_network_allowed(req) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
    }

    httpd_resp_set_type(req, "application/json");
    
    // Set CORS headers
    if (set_cors_headers(req) != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    // For now, just return success (no actual email functionality)
    JsonDocument response;
    response["success"] = true;
    response["messages"] = JsonArray();
    response["messages"][0] = "Password reset instructions sent (not implemented)";
    
    ESP_LOGI(TAG, "Password reset requested");
    esp_err_t ret = sendJsonResponse(req, response);
    return ret;
    return ESP_OK;
}

/* Reset password endpoint */
esp_err_t POST_auth_reset_pass(httpd_req_t *req) {
    if (is_network_allowed(req) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
    }

    httpd_resp_set_type(req, "application/json");
    
    // Set CORS headers
    if (set_cors_headers(req) != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    // For now, just return success (password reset not fully implemented)
    JsonDocument response;
    response["success"] = true;
    response["messages"] = JsonArray();
    response["messages"][0] = "Password reset successful (not implemented)";
    
    ESP_LOGI(TAG, "Password reset completed");
    esp_err_t ret = sendJsonResponse(req, response);
    return ret;
    return ESP_OK;
}

/* Refresh token endpoint */
esp_err_t POST_auth_refresh_token(httpd_req_t *req) {
    if (is_network_allowed(req) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
    }

    httpd_resp_set_type(req, "application/json");
    
    // Set CORS headers
    if (set_cors_headers(req) != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char token[65];
    if (!extract_bearer_token(req, token, sizeof(token)) || !is_valid_session(token)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Invalid or expired token");
        return ESP_FAIL;
    }

    // Generate new session token
    generate_session_token(current_session_token, sizeof(current_session_token));
    
    // Extend expiry to 24 hours from now
    session_expiry = time(NULL) + (24 * 60 * 60);
    
    // Create response
    JsonDocument response;
    response["success"] = true;
    response["data"]["token"] = current_session_token;
    response["data"]["expires"] = session_expiry;
    response["messages"] = JsonArray();
    
    ESP_LOGI(TAG, "Token refreshed");
    esp_err_t ret = sendJsonResponse(req, response);
    return ret;
    return ESP_OK;
}