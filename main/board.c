/*
 * board.c – now-hub board-level WiFi init
 *
 * Provides the dev_wifi_init() hook expected by the fh_portal component.
 * The now-hub has no antenna switch (unlike the Xiao ESP32-C6 boards),
 * so this just calls esp_wifi_init() and sets the country code.
 */

#include "esp_wifi.h"

esp_err_t dev_wifi_init(wifi_init_config_t *config)
{
    esp_err_t err = esp_wifi_init(config);
    if (err == ESP_OK) {
        wifi_country_t country = {
            .cc     = "EU",
            .schan  = 1,
            .nchan  = 13,
            .policy = WIFI_COUNTRY_POLICY_MANUAL,
        };
        esp_wifi_set_country(&country);
    }
    return err;
}
