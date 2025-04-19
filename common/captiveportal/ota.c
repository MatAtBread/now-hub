#include "ota.h"

#include "esp_ota_ops.h"
#include "esp_log.h"
#include <string.h>

#define OTA_BUFF_SIZE 1024
extern const char* TAG;

esp_err_t ota_post_handler(httpd_req_t *req)
{
    esp_ota_handle_t ota_handle = 0;
    const esp_partition_t *ota_partition = esp_ota_get_next_update_partition(NULL);
    char ota_buff[OTA_BUFF_SIZE];
    int received, remaining = req->content_len;

    ESP_LOGI(TAG, "Starting OTA update, total size: %d", req->content_len);

    if (esp_ota_begin(ota_partition, OTA_SIZE_UNKNOWN, &ota_handle) != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA Begin Failed");
        return ESP_FAIL;
    }

    while (remaining > 0) {
        received = httpd_req_recv(req, ota_buff, MIN(remaining, OTA_BUFF_SIZE));
        if (received <= 0) {
            ESP_LOGE(TAG, "Error in receiving OTA data");
            esp_ota_end(ota_handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Receive Error");
            return ESP_FAIL;
        }
        if (esp_ota_write(ota_handle, ota_buff, received) != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write failed");
            esp_ota_end(ota_handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Write Error");
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "OTA data remaiining: %d", remaining);
        remaining -= received;
    }

    if (esp_ota_end(ota_handle) != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA End Failed");
        return ESP_FAIL;
    }

    if (esp_ota_set_boot_partition(ota_partition) != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Set Boot Partition Failed");
        return ESP_FAIL;
    }

    httpd_resp_sendstr(req, "OTA update successful. Rebooting...");
    ESP_LOGI(TAG, "OTA update successful. Rebooting...");
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    esp_restart();
    return ESP_OK;
}
