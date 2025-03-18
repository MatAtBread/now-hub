#include "nvs_flash.h"
#include "esp_now.h"
#include "esp_wifi.h"
#include "mqtt_client.h"
#include "esp_log.h"
#include <string.h>

#include <string>

#define MQTT_TOPIC      "espnow"
#define CONFIG_MQTT_BROKER_URL "mqtt://house.mailed.me.uk:1883"

#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC2STR(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]

static const char *TAG = "mqtt-"MQTT_TOPIC;

/*
ESP-NOW messages are strings:
    PAIR:NAME           Pair the source MAC with the specified NAME, supporting the specified fields in JSON. This is broadcast from the end device and processed by the hub.
    PACK                Sent in response to a PAIR message, confirms the pairing allowing the client to pair with the hub
    {json}              Sent from MQTT broker to end-device and from end-device to MQTT broker. Validation is done by the end-device and/or the broker. This hub doesn't validate the date

MQTT topics:
    espnow/NAME/status  Status message forwarded by the hub deom the esp-now device to the MQTT broker
    espnow/NAME         Data message sent by other devices to the hub, destined for the esp-now device with the specified NAME
*/

typedef uint8_t MACAddr[6];

#define MAX_DEVICES ESP_NOW_MAX_TOTAL_PEER_NUM

static MACAddr deviceMac[MAX_DEVICES] = {};
static char* deviceName[MAX_DEVICES] = {};

static esp_mqtt_client_handle_t mqtt_client;
static uint8_t gateway_mac[6];

static int findDeviceMac(const uint8_t *mac) {
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (memcmp(deviceMac[i], mac, sizeof deviceMac[0]) == 0) {
            return i;
        }
    }
    return -1;
}

static int findDeviceName(const char *name) {
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (deviceName[i] && strcmp(deviceName[i], name) == 0) {
            return i;
        }
    }
    return -1;
}

static void send_mqtt(const uint8_t *mac, const uint8_t *data, size_t len) {
    const auto deviceIndex = findDeviceMac(mac);
    if (deviceIndex == -1) {
        ESP_LOGE(TAG, "Unknown device "MACSTR, MAC2STR(mac));
        return;
    }

    std::string topic = MQTT_TOPIC "/";
    topic += deviceName[deviceIndex];
    topic += "/status";

    esp_mqtt_client_publish(mqtt_client, topic.c_str(), (const char *)data, len, 1, 0);
}

static void mqtt_event_handler(void *args, esp_event_base_t base,
                              int32_t event_id, void *event_data) {
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    if (event->event_id == MQTT_EVENT_CONNECTED) {
        // esp_mqtt_client_publish(mqtt_client, MQTT_TOPIC, "active", 6, 1, 0);
        esp_mqtt_client_subscribe(mqtt_client, MQTT_TOPIC "/#", 1);
    } else if (event->event_id == MQTT_EVENT_DATA) {
        // Extract target MAC from topic
        char *topic = (char *)malloc(event->topic_len + 1);
        memcpy(topic, event->topic, event->topic_len);
        topic[event->topic_len] = 0;

        char *name = strrchr(topic, '/') + 1;
        if (!name) {
            ESP_LOGI(TAG, "Missing name %s", name);
            free(topic);
            return;
        }
        char *subtopic = strchr(name, '/');
        if (subtopic) {
            ESP_LOGD(TAG, "Ignore status message for %s", name);
            free(topic);
            return; // Ignore our own status messages
        }

        const auto deviceIndex = findDeviceName(name);
        if (deviceIndex == -1) {
            ESP_LOGI(TAG, "Unknown device %s", name);
            free(topic);
            return;
        }

        if (event->data_len >= ESP_NOW_MAX_DATA_LEN_V2) {
            ESP_LOGI(TAG, "Too much data for esp-now v2: %s %s", name, event->data);
        } else {
            auto target = deviceMac[deviceIndex];
            esp_now_send(target, (uint8_t*)event->data, event->data_len);
        }
        free(topic);
    } else {
        ESP_LOGI(TAG, "Unhandled MQTT event: %d", event->event_id);
    }
}

static uint32_t PAIR = *((const uint32_t *)"PAIR");
static uint32_t PACK = *((const uint32_t *)"PACK");

static void espnow_recv_cb(const esp_now_recv_info_t *esp_now_info, const uint8_t *data, int len) {
    if ((*(const uint32_t *)data) == PAIR) {
        // This is a request to pair
        ESP_LOGI(TAG, "PAIR "MACSTR, MAC2STR(esp_now_info->src_addr));
        esp_now_peer_info_t peer;
        memset(&peer, 0, sizeof (peer));
        peer.ifidx = WIFI_IF_STA;
        memcpy(&peer.peer_addr, esp_now_info->src_addr, sizeof (MACAddr));

        esp_now_add_peer(&peer);
        esp_now_send(esp_now_info->src_addr, (const uint8_t*)PACK, sizeof(PACK));
    } else if (*data == '{') {
        // Some JSON we need to forward to the MQTT broker
        auto deviceIndex = findDeviceMac(esp_now_info->src_addr);
        if (deviceIndex >= 0) {
            std::string topic = MQTT_TOPIC "/";
            topic += deviceName[deviceIndex];
            esp_mqtt_client_publish(mqtt_client, topic.c_str(), (const char*)data, len, 1, 0);
        } else {

        }
    } else {
        ESP_LOGI(TAG, "Unknown message from "MACSTR, MAC2STR(esp_now_info->src_addr));
    }
}

static EventGroupHandle_t wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

// Event handler for WiFi and IP events
static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "WiFi started, connecting...");
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        ESP_LOGI(TAG, "WiFi connected.");
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGE(TAG, "WiFi disconnected. Retrying...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

extern "C" void app_main(void) {
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize TCP/IP stack and WiFi
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *netif = esp_netif_create_default_wifi_sta(); // Create default STA interface

    wifi_event_group = xEventGroupCreate();

    // Register event handler
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    // Set SSID and password
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = "top.mailed.me.uk",
            .password = "1finityCML",
            .threshold = { .authmode = WIFI_AUTH_WPA2_PSK },
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

    // Start WiFi
    ESP_ERROR_CHECK(esp_wifi_start());

    // Wait for connection
    ESP_LOGI(TAG, "Connecting to WiFi...");
    xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    // Get MAC address
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, gateway_mac));

    uint8_t primary_channel;
    wifi_second_chan_t secondary_channel = WIFI_SECOND_CHAN_NONE;
    esp_err_t result = esp_wifi_get_channel(&primary_channel, &secondary_channel);

    if (result == ESP_OK) {
        ESP_LOGI(TAG,
                 "WiFi connected %s: Primary channel: %d, Secondary channel: %d, MAC %02x:%02x:%02x:%02x:%02x:%02x",
                 wifi_config.sta.ssid,
                 primary_channel,
                 secondary_channel,
                 gateway_mac[0],
                 gateway_mac[1],
                 gateway_mac[2],
                 gateway_mac[3],
                 gateway_mac[4],
                 gateway_mac[5]);
    } else {
        ESP_LOGE(TAG, "Failed to get channel: %d", result);
        return;
    }

    // Initialize ESP-NOW
    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_recv_cb));

    // Initialize MQTT
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker = { .address = { .uri = CONFIG_MQTT_BROKER_URL } },
        .network = { .disable_auto_reconnect = false }
    };

    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(mqtt_client, (esp_mqtt_event_id_t)ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(mqtt_client);
}
