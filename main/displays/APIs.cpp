#include "APIs.h"
#include "cJSON.h"
#include "esp_err.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "HTTPClient.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "nvs_flash.h"
#include <stdlib.h>
#include <string.h>

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

static char tag[] = "APIsHelper";
static char *response_buffer = NULL; // Buffer para acumular la respuesta completa
static int response_length = 0;      // Longitud actual del buffer
static unsigned long mBTCUpdate = 0;
static unsigned int bitcoin_price = 0; // Establece esta variable globalmente

// Handler de eventos para la respuesta HTTP
esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    switch (evt->event_id) {
    case HTTP_EVENT_ON_DATA: {
        if (!esp_http_client_is_chunked_response(evt->client)) {
            // Aumentar el buffer con nuevos datos
            char *new_buffer = (char*) realloc(response_buffer, response_length + evt->data_len + 1);
            if (new_buffer == NULL) {
                ESP_LOGE(tag, "Failed to allocate memory for response buffer");
                return ESP_ERR_NO_MEM;
            }
            response_buffer = new_buffer;
            memcpy(response_buffer + response_length, (char *) evt->data, evt->data_len);
            response_length += evt->data_len;
            response_buffer[response_length] = '\0'; // Asegurarse de que el buffer es una cadena válida
        }
        break;
    }
    case HTTP_EVENT_ON_FINISH: {
        // Intentar parsear el JSON completo al final de la transmisión
        // ESP_LOGI(tag, "Final JSON received: %s", response_buffer);
        cJSON *json = cJSON_Parse(response_buffer);
        if (json != NULL) {
            cJSON *bpi = cJSON_GetObjectItem(json, "bpi");
            if (bpi != NULL) {
                cJSON *usd = cJSON_GetObjectItem(bpi, "USD");
                if (usd != NULL) {
                    cJSON *rate_float = cJSON_GetObjectItem(usd, "rate_float");
                    if (cJSON_IsNumber(rate_float)) {
                        bitcoin_price = (int) rate_float->valuedouble;
                        ESP_LOGI(tag, "Bitcoin price in USD: %d", bitcoin_price);
                    }
                }
            }
            cJSON_Delete(json);
        } else {
            ESP_LOGE(tag, "Failed to parse JSON");
        }
        // Liberar el buffer después de procesar
        free(response_buffer);
        response_buffer = NULL;
        response_length = 0;
        break;
    }
    default:
        break;
    }
    return ESP_OK;
}

unsigned int getBTCprice(void)
{

    if ((mBTCUpdate == 0) || (esp_timer_get_time() / 1000 - mBTCUpdate > UPDATE_BTC_min * 60)) {
        HTTPClient http;
      try {
          // Use the new API endpoint
          http.begin(getBTCAPI);
          int httpCode = http.GET();

          if (httpCode == HTTP_CODE_OK) {
              String payload = http.getString();

              // Parse the JSON response
              DynamicJsonDocument doc(2048); // Increase size if needed
              deserializeJson(doc, payload);

              // Extract the Bitcoin price from the new API response
              if (doc.containsKey("quotes") && doc["quotes"].containsKey("USD")) {
                  bitcoin_price = doc["quotes"]["USD"]["price"].as<double>();
              }

              doc.clear();

              // Update the last fetch time
              mBTCUpdate = millis();
          }

          http.end();
      } catch (...) {
          http.end();
      }
    }

    return bitcoin_price;
}
