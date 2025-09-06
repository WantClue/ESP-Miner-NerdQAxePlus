#pragma once

#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Authentication handlers */
esp_err_t POST_auth_signin(httpd_req_t *req);
esp_err_t POST_auth_signout(httpd_req_t *req);
esp_err_t POST_auth_request_pass(httpd_req_t *req);
esp_err_t POST_auth_reset_pass(httpd_req_t *req);
esp_err_t POST_auth_refresh_token(httpd_req_t *req);

/* Authentication middleware */
bool is_authenticated(httpd_req_t *req);

#ifdef __cplusplus
}
#endif