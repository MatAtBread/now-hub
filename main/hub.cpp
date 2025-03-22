#include "nvs_flash.h"
#include "esp_now.h"
#include "esp_wifi.h"
#include "mqtt_client.h"
#include "esp_log.h"
#include <string.h>

#include <string>
#include <sstream>

// These should be configurable

const char *MQTT_TOPIC = "FreeHouse";
const char *CONFIG_MQTT_BROKER_URL = "mqtt://house.mailed.me.uk:1883";

#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC2STR(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]

#define RETAIN  1

static const char *TAG = "ESPNOW-HUB";
static const char PAIR_DELIM[]  = ":";

/*
ESP-NOW messages are strings:
    PAIRname:topic:info  Pair the source MAC with the specified NAME, supporting the specified fields in JSON. This is broadcast from the end device and processed by the hub. The :INFO is optional an informational, like a User Agent
    PACK                Sent in response to a PAIR message, confirms the pairing allowing the client to pair with the hub
    {json}              Sent from MQTT broker to end-device and from end-device to MQTT broker. Validation is done by the end-device and/or the broker. This hub doesn't validate the date

MQTT topics:
    FreeHouse/NAME/status   Status message forwarded by the hub deom the esp-now device to the MQTT broker
    FreeHouse/NAME          Data message sent by other devices to the hub, destined for the esp-now device with the specified NAME
    FreeHouse               Hub status
*/

typedef uint8_t MACAddr[6];
typedef char device_name_t[20];

#define MAX_DEVICES ESP_NOW_MAX_TOTAL_PEER_NUM

static MACAddr deviceMac[MAX_DEVICES] = {};
static device_name_t deviceName[MAX_DEVICES] = {};
static char *deviceInfo[MAX_DEVICES] = {};
static int peerRssi[MAX_DEVICES] = {};

static MACAddr noDevice = {0,0,0,0,0,0};

static esp_mqtt_client_handle_t mqtt_client;
static uint8_t gateway_mac[6];

static int findDeviceMac(const uint8_t *mac) {
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (memcmp(&deviceMac[i], mac, sizeof deviceMac[0]) == 0) {
            return i;
        }
    }
    ESP_LOGW(TAG, "No paired device for MAC "MACSTR, MAC2STR(mac));
    return -1;
}

static int findDeviceName(const char *name) {
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (strncmp(deviceName[i], name, sizeof (device_name_t)) == 0) {
            return i;
        }
    }
    ESP_LOGW(TAG, "No paired device for '%s'", name);
    return -1;
}

static std::string hubStatusJson() {
    std::stringstream s;
    s << "[";
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (deviceName[i][0]) {
            char mac[20];
            sprintf(mac,MACSTR,MAC2STR(deviceMac[i]));
            s << "{"
            "\"name\":\"" << deviceName[i] << "\","
            "\"mac\":\"" << mac << "\","
            "\"rssi\":" << peerRssi[i] << ","
            "\"info\":" << (char *)(deviceInfo[i] ? deviceInfo[i] : "null") <<
            "}";
        }
    }
    s << "]";
    return s.str();
}

/** malloc'd return - caller must free */
static char *bufAs0TermString(const void *s, size_t n) {
    char *d = (char *)malloc(n + 1);
    memcpy(d, s, n);
    d[n] = 0;
    return d;
}

static void mqtt_event_handler(void *args, esp_event_base_t base,
                               int32_t event_id, void *event_data) {
  esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
  if (event->event_id == MQTT_EVENT_CONNECTED) {
    esp_mqtt_client_publish(mqtt_client, MQTT_TOPIC, hubStatusJson().c_str(), 0, 1, RETAIN);
    std::string topic =  MQTT_TOPIC;
    topic += "/#";
    esp_mqtt_client_subscribe(mqtt_client, topic.c_str(), 1);
  } else if (event->event_id == MQTT_EVENT_DATA) {
    // Check if we're talking to ourselves
    char *topic = bufAs0TermString(event->topic, event->topic_len);
    if (!strcmp(topic,MQTT_TOPIC)) {
        ESP_LOGD(TAG, "Ignore hub mqtt message");
        free(topic);
        return;
    }

    char *name = strchr(topic, '/');
    if (!name) {
      ESP_LOGI(TAG, "Missing name %s", topic);
      free(topic);
      return;

    }
    name += 1;  // Skip the '/'
    char *subtopic = strchr(name, '/');
    if (subtopic) {
      ESP_LOGD(TAG, "Ignore status message for %s", name);
      free(topic);
      return;  // Ignore our own status messages
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
      auto str = (uint8_t *)bufAs0TermString(event->data, event->data_len);
      esp_now_send(target, str, event->data_len + 1);
      free(str);
    }
    free(topic);
  } else {
    ESP_LOGI(TAG, "Unhandled MQTT event: %d", event->event_id);
  }
}

static uint32_t PAIR[] = {*((const uint32_t *)"PAIR"), 0};
static uint32_t PACK[] = {*((const uint32_t *)"PACK"),0};

static void espnow_recv_cb(const esp_now_recv_info_t *esp_now_info, const uint8_t *data, int len) {
    if ((*(const uint32_t *)data) == PAIR[0]) {
        // This is a request to pair
        auto deviceIndex = findDeviceMac(esp_now_info->src_addr);
        if (deviceIndex < 0) {
            for (int i = 0; i<MAX_DEVICES; i++) {
                if (!memcmp(noDevice, &deviceMac[i], sizeof (noDevice))) {
                    deviceIndex = i;
                    ESP_LOGI(TAG, "Assign "MACSTR": slot %d", MAC2STR(esp_now_info->src_addr), deviceIndex);
                    break;
                }
            }
        }
        if (deviceIndex >= 0) {
            char *name = bufAs0TermString(data + 4, len-4);
            ESP_LOGI(TAG, "PAIR "MACSTR": %s", MAC2STR(esp_now_info->src_addr), name);
            strtok(name,PAIR_DELIM);
            char *hub = strtok(NULL, PAIR_DELIM);
            if (!hub || strcmp(hub,MQTT_TOPIC)) {
                // Pairing request was meant for a different network
                free(name);
                return;
            }
            char *info = strtok(NULL, "");
            if (info) {
                if (deviceInfo[deviceIndex]) free(deviceInfo[deviceIndex]);
                deviceInfo[deviceIndex] = bufAs0TermString(info, strlen(info));
            }
            memcpy(&deviceMac[deviceIndex], esp_now_info->src_addr, sizeof (MACAddr));
            strncpy(deviceName[deviceIndex], name, sizeof (device_name_t));
            free(name);

            peerRssi[deviceIndex] = esp_now_info->rx_ctrl->rssi;

            if (!esp_now_is_peer_exist(esp_now_info->src_addr)) {
                esp_now_peer_info_t peer;
                memset(&peer, 0, sizeof (peer));
                peer.ifidx = WIFI_IF_STA;
                memcpy(&peer.peer_addr, esp_now_info->src_addr, sizeof (MACAddr));

                esp_now_add_peer(&peer);
            }
            esp_now_send(esp_now_info->src_addr, (const uint8_t*)PACK, sizeof(PACK));
            esp_mqtt_client_publish(mqtt_client, MQTT_TOPIC, hubStatusJson().c_str(), 0, 1, RETAIN);
        } else {
            ESP_LOGE(TAG, "No device space for pairing %s "MACSTR, data + 4, MAC2STR(esp_now_info->src_addr));
        }
    } else if (*data == '{') {
        // Some JSON we need to forward to the MQTT broker
        auto deviceIndex = findDeviceMac(esp_now_info->src_addr);
        if (deviceIndex >= 0) {
            peerRssi[deviceIndex] = esp_now_info->rx_ctrl->rssi;
            std::string topic = MQTT_TOPIC;
            topic += "/";
            topic += deviceName[deviceIndex];
            topic += "/status";

            esp_mqtt_client_publish(mqtt_client, topic.c_str(), (const char*)data, len, 1, RETAIN);
            esp_mqtt_client_publish(mqtt_client, MQTT_TOPIC, hubStatusJson().c_str(), 0, 1, RETAIN);
        }
    } else {
        ESP_LOGI(TAG, "Unknown message from "MACSTR " %s", MAC2STR(esp_now_info->src_addr), data);
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
