#include <string.h>

#include <sstream>
#include <string>

#include "../common/captiveportal/wifi-captiveportal.h"
#include "../common/gpio/gpio.hpp"
#include "./read_write_lock/rwl.hpp"
#include "esp_log.h"
// #include "esp_heap_trace.h"
#include "esp_now.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "mqtt_client.h"
#include "nvs_flash.h"
#include "cJSON.h"

#define BUILD_TIMESTAMP __DATE__ " " __TIME__
#define MULTILINE_STRING(...) #__VA_ARGS__

// These should be configurable
const char *MQTT_TOPIC = "FreeHouse";
#define OTA_ROOT_URI "http://files.mailed.me.uk/public/freehouse/"
#define IO_LED_R 3
#define IO_LED_G 4
#define IO_LED_B 5
#define IO_BUTTON 9

#define DEVICE_TIMEOUT 60 * 60 *1000UL  // 1 hour
#define MQTT_BUFFER_SIZE  8192
#define MQTT_LATENCY      100 // A guess at how many ms it takes for a hubStatus message to get through the MQTT broker. It is wrong a second run should pick it up

//#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
//#define MAC2STR(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]

#define RETAIN 1

const char *TAG = "ESPNOW-HUB";
static const char PAIR_DELIM[] = ":";

/*
ESP-NOW messages are strings:
    PAIRname:topic:info  Pair the source MAC with the specified NAME, supporting the specified fields in JSON. This is broadcast from the end device and processed by the hub. The :INFO is optional an informational, like a User Agent
    PACK                Sent in response to a PAIR message, confirms the pairing allowing the client to pair with the hub
    {json}              Sent from MQTT broker to end-device and from end-device to MQTT broker. Validation is done by the end-device and/or the broker. This hub doesn't validate the date

MQTT topics:
    FreeHouse/NAME          The state of the device: a message forwarded by the hub from the esp-now device to the MQTT broker (ie hub RX, )
    FreeHouse/NAME/set      Data message sent by other devices to the hub, destined for the esp-now device with the specified NAME. Note: multiple messages are shallow merged until they are delivered.
    FreeHouse               Hub status
*/

typedef uint8_t MACAddr[6];
typedef char device_name_t[32];

typedef struct {
  MACAddr mac;
  device_name_t name;
  char *info;
  int peerRssi;
  std::string pending;  // Accumulated JSON for any messages that failed to arrive at the destination device, to be sent on the next connection
  uint32_t lastSeen;    // Timestamp (esp_log time) we last saw this device, or 0 to mark it as needing to be unpaired
} device_t;

typedef device_t device_table_t[ESP_NOW_MAX_TOTAL_PEER_NUM];
static SerializedStatic<device_table_t>* devices;
static bool hubStatusChanged = false;

static MACAddr noDevice = {0, 0, 0, 0, 0, 0};

static esp_mqtt_client_handle_t mqtt_client;
static uint8_t gateway_mac[6] = {0};
static char hub_ip[16] = {0};
static char hostname[32] = {0};
static wifi_config_t wifi_config = {
  .sta = {
      .ssid = "",
      .password = "",
      .threshold = {.authmode = WIFI_AUTH_WPA2_PSK},
  }
};

static device_t *findDeviceMac(Locked<device_table_t>& device, const uint8_t *mac) {
  for (int i = 0; i < ESP_NOW_MAX_TOTAL_PEER_NUM; i++) {
    if (memcmp(device[i].mac, mac, sizeof(device[i].mac)) == 0) {
      // ESP_LOGI(TAG, "Found device %d " MACSTR " " MACSTR, i, MAC2STR(mac), MAC2STR(mac));
      return &device[i];
    }
  }
  return NULL;
}

static device_t* findDeviceName(Locked<device_table_t>& device, const char *name) {
  for (int i = 0; i < ESP_NOW_MAX_TOTAL_PEER_NUM; i++) {
    if (strncmp(device[i].name, name, sizeof(device_name_t)) == 0) {
      return device + i;
    }
  }
  return NULL;
}

static void unpairDevice(device_t *dev, const char *reason) {
  if (dev != NULL) {
    ESP_LOGI(TAG, "Unpair (%s) dev %p " MACSTR " (%s)", reason, dev, MAC2STR(dev->mac), dev->name);
    MACAddr mac;
    memcpy(mac,dev->mac, sizeof (mac));
    memset(dev->name, 0, sizeof(dev->name));
    memset(dev->mac, 0, sizeof(dev->mac));
    dev->pending = "";
    dev->lastSeen = 0;
    dev->peerRssi = 0;

    if (dev->info) free(dev->info);
    dev->info = NULL;
    if (esp_now_is_peer_exist(mac)) {
      esp_now_del_peer(mac);
    }
  }
}

static std::string metaJson(const device_t *dev) {
  std::stringstream s;
  char mac[20];
  sprintf(mac, MACSTR, MAC2STR(dev->mac));
  s << "{"
    "\"name\":\"" << dev->name << "\","
    "\"hub\":\"" << hub_ip << "\","
    "\"mac\":\"" << mac << "\","
    "\"rssi\":" << dev->peerRssi << ","
    "\"info\":" << (char *)(dev->info ? dev->info : "null") << ","
    "\"lastSeen\":" << (signed)(esp_log_timestamp() - dev->lastSeen)
    << "}";
  return s.str();
}

static std::string hubStatusJson(Locked<device_table_t> &device) {
  std::stringstream s;
  bool comma = false;
  s << "[";
  for (int i = 0; i < ESP_NOW_MAX_TOTAL_PEER_NUM; i++) {
    const device_t* dev = &device[i];
    if (dev->lastSeen && dev->name[0]) {
      if (comma) s << ",";
      comma = true;
      s << metaJson(dev);
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

static uint8_t hexValue(const char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return 0;
}

static void macFromHex12(const char *hex, MACAddr &mac, bool commas) {
  int step = commas ? 3 : 2;
  memset(mac,0,sizeof (mac));
  for (int i = 0; i < 6; i++) {
    mac[i] = hexValue(hex[i * step]) * 16 + hexValue(hex[i * step + 1]);
  }
}

cJSON *shallow_merge(const char *dest_json_str, const char *src_json_str) {
  // Parse destination and source JSON strings
  cJSON *dest = cJSON_Parse(dest_json_str);
  cJSON *src = cJSON_Parse(src_json_str);

  if (!dest || !src) {
      printf("Error parsing JSON strings.\n");
      if (dest) cJSON_Delete(dest);
      if (src) cJSON_Delete(src);
      return NULL;
  }

  // Iterate through keys in the source object
  cJSON *src_item = src->child;
  while (src_item) {
      // Find the corresponding key in the destination object
      cJSON *dest_item = cJSON_GetObjectItem(dest, src_item->string);

      if (dest_item) {
          // Replace value in destination with value from source (shallow update)
          cJSON_ReplaceItemInObject(dest, src_item->string, cJSON_Duplicate(src_item, 1));
      } else {
          // Add new key-value pair to destination
          cJSON_AddItemToObject(dest, src_item->string, cJSON_Duplicate(src_item, 1));
      }

      src_item = src_item->next; // Move to next key in source
  }

  // Cleanup source object
  cJSON_Delete(src);

  // ESP_LOGI(TAG, "Merged JSON: %s = %s + %s", cJSON_Print(dest), dest_json_str, src_json_str); // Print merged JSON for debugging
  return dest; // Return merged JSON object
}

static void checkPromiscuousDevices(Locked<device_table_t> &device,  const char *src) {
  cJSON *hubMsg = cJSON_Parse(src);
  if (hubMsg) {
    if (cJSON_IsArray(hubMsg)) {
      cJSON *elt = NULL;
      auto now = esp_log_timestamp();
      cJSON_ArrayForEach(elt, hubMsg) {
        if (cJSON_IsObject(elt)) {
          cJSON *name = cJSON_GetObjectItem(elt, "name");
          cJSON *hub = cJSON_GetObjectItem(elt, "hub");
          cJSON *mac = cJSON_GetObjectItem(elt, "mac");
          cJSON *lastSeen = cJSON_GetObjectItem(elt, "lastSeen");

          // Verify both are strings before using
          if (cJSON_IsString(hub) && cJSON_IsString(mac) && cJSON_IsNumber(lastSeen)) {
            // If the message is NOT from us...
            MACAddr devMac;
            macFromHex12(mac->valuestring, devMac, true);
            // If we know about this device, and saw it **from another hub** more recently than we did, unpair it by forcing the local lastSeen to 0
            auto dev = findDeviceMac(device, devMac);
            if (dev != NULL && dev->lastSeen && lastSeen->valueint + MQTT_LATENCY < (now - dev->lastSeen) && strcmp(hub_ip, hub->valuestring) != 0) {
              ESP_LOGI(TAG, "Device %s (%s, " MACSTR ") was seen on hub %.80s (we are %s) %dms ago. We saw it %lums ago",
                name ? name->valuestring : "?",
                mac->valuestring, MAC2STR(devMac),
                hub->valuestring, hub_ip,
                lastSeen->valueint + MQTT_LATENCY,
                now - dev->lastSeen
              );
              dev->lastSeen = 0; // This will make it look like this device has been offline for ages
            }
          } else {
            ESP_LOGI(TAG, "checkPromiscuousDevices missing mac/hub/lastSeen: 0x%x 0x%x 0x%x", mac ? mac->type : cJSON_Invalid, hub ? hub->type : cJSON_Invalid, lastSeen ? lastSeen->type : cJSON_Invalid);
          }
        } else {
          ESP_LOGI(TAG, "checkPromiscuousDevices not a JSON object: %.80s", elt->string);
        }
      }
    } else {
      ESP_LOGI(TAG, "checkPromiscuousDevices not a JSON array: %.80s", src);
    }
    cJSON_Delete(hubMsg);
  } else {
    ESP_LOGW(TAG, "checkPromiscuousDevices not JSON: %p", src);
    // Dump as hex??
  }
}

static void mergeAndSendPending(device_t *device, const char *str) {
  // Check if the device index is valid
  if (device == NULL) {
    ESP_LOGE(TAG, "Invalid device index");
    return;
  }

  if (!memcmp(noDevice, device->mac, sizeof(noDevice))) {
    ESP_LOGE(TAG, "Invalid device mac: " MACSTR, MAC2STR(device->mac));
    return;
  }

  // Check if the pending string is not empty
  if (!str || strlen(str) == 0) {
    ESP_LOGE(TAG, "Empty pending string");
    return;
  }

  // Check if the device has a pending message
  if (device->pending.length()) {
    // Merge pending messages
    auto merged = shallow_merge(device->pending.c_str(), str);
    if (merged) {
      // Print merged JSON string
      char *merged_json_str = cJSON_PrintUnformatted(merged);
      device->pending = merged_json_str;
      free(merged_json_str);
      // Free memory
      cJSON_Delete(merged);
    } else {
      device->pending = str;
    }
  } else {
    device->pending = str;
  }

  ESP_LOGD(TAG, "Send " MACSTR " pending (merge)", MAC2STR(device->mac));
  esp_now_send(device->mac, (const uint8_t *)device->pending.c_str(), device->pending.length() + 1);
}

static int mqtt_client_publish(esp_mqtt_client_handle_t client, const char *topic, const char *data, int len, int qos, int retain) {
  auto r = esp_mqtt_client_publish(client, topic, data, len, qos, retain);
  if (r < 0) {
    ESP_LOGW(TAG,"mqtt_client_publish %s (%d) failed with %d", topic, len, r);
  }
  return r;
}

static void mqtt_event_handler(void *args, esp_event_base_t base,
                               int32_t event_id, void *event_data) {
  esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

  switch (event->event_id) {
    case MQTT_EVENT_CONNECTED: {
      hubStatusChanged = true;
      std::string topic = MQTT_TOPIC;
      topic += "/#";
      esp_mqtt_client_subscribe(mqtt_client, topic.c_str(), 1);
    } break;

    case MQTT_EVENT_DATA: {
      // Check if we're talking to ourselves, specifically we need to check the topic looks like "FreeHouse/NAME/set"
      // and the data is a JSON string. We don't care about the rest of the MQTT stuff.

      char *topic = bufAs0TermString(event->topic, event->topic_len);
      char *root = strtok(topic, "/");
      char *name = strtok(NULL, "/");
      char *subtopic = strtok(NULL, "/");
      Locked device(devices);
      device_t *dev;

      // We ARE interested in the FreeHouse topic (with no subtop [device]) as we can listen to it, and
      // if we hear that one of our devices has attached to another hub we can unpair it
      ESP_LOGD(TAG,"MQTT_EVENT_DATA %s (root %s, name %s, subtopic %s)", topic ? topic : "NULL", root ? root : "NULL", name ? name : "NULL", subtopic ? subtopic : "NULL");
      if (!name && !subtopic && root && !strcmp(root, MQTT_TOPIC)) {
        // This should be JSON array in the format returned by hubStatusJson()
        auto str = std::string(event->data, event->data_len);
        checkPromiscuousDevices(device, str.c_str());
      } else {
        if (!name || !subtopic || strcmp(root, MQTT_TOPIC) || strcmp(subtopic, "set") || (dev = findDeviceName(device, name)) == NULL) {
          ESP_LOGV(TAG, "Ignore hub mqtt message %s/%s/%s", root ? root : "?", name ? name : "?", subtopic ? subtopic : "?");
        } else {
          if (event->data_len >= ESP_NOW_MAX_DATA_LEN_V2) {
            ESP_LOGI(TAG, "Too much data for esp-now v2: %s %s", name, event->data);
          } else {
            auto str = std::string(event->data, event->data_len);
            mergeAndSendPending(dev, str.c_str());
          }
        }
      }
      free(topic);
    } break;

    case MQTT_EVENT_PUBLISHED:
    case MQTT_EVENT_SUBSCRIBED:
    case MQTT_EVENT_BEFORE_CONNECT:
      break;

    default:
      ESP_LOGI(TAG, "Unhandled MQTT event: %d", event->event_id);
  }
}

static uint32_t PAIR[] = {*((const uint32_t *)"PAIR"), 0};
static uint32_t PACK[] = {*((const uint32_t *)"PACK"), 0};
static uint32_t NACK[] = {*((const uint32_t *)"NACK"), 0};

static void sendNACK(const uint8_t *mac_addr) {
  if (!esp_now_is_peer_exist(mac_addr)) {
    esp_now_peer_info_t peer;
    memset(&peer, 0, sizeof(peer));
    peer.ifidx = WIFI_IF_STA;
    memcpy(&peer.peer_addr, mac_addr, sizeof(MACAddr));

    esp_now_add_peer(&peer);
  }
  ESP_LOGD(TAG, "Send " MACSTR " NACK", MAC2STR(mac_addr));
  // vTaskDelay(50 / portTICK_PERIOD_MS); // We need to delay otherwise we delete the peer too quickly. [upd: just let it fail]
  esp_now_send(mac_addr, (uint8_t *)NACK, sizeof(NACK));
  esp_now_del_peer(mac_addr);
}

static void espnow_send_cb(const uint8_t *mac_addr, esp_now_send_status_t status) {
  Locked device(devices);
  const auto dev = findDeviceMac(device, mac_addr);

  if (status != ESP_OK) {
    // debug, as it will be sent when the device connects with a PACK from the .pending member
    ESP_LOGD(TAG, "Send to " MACSTR " (device %s) failed", MAC2STR(mac_addr), dev ? dev->name : "?");
  } else {
    if (dev != NULL) {
      if (dev->pending.length()) {
        ESP_LOGD(TAG, "Delivered to %s: %s", dev->name, dev->pending.c_str());
        dev->pending = "";
      }
    }
  }
}

static void espnow_recv_cb(const esp_now_recv_info_t *esp_now_info, const uint8_t *data, int len) {
  device_t *dev;
  {
    Locked device(devices);
    dev = findDeviceMac(device, esp_now_info->src_addr);
  }

  if ((*(const uint32_t *)data) == PAIR[0]) {
    // This is a request to pair
    if (dev == NULL) {
      Locked device(devices);
      for (int i = 0; i < ESP_NOW_MAX_TOTAL_PEER_NUM; i++) {
        if (!memcmp(noDevice, device[i].mac, sizeof(noDevice))) {
          dev = &device[i];
          ESP_LOGI(TAG, "Assign " MACSTR " to slot %d [%.*s]", MAC2STR(esp_now_info->src_addr), i, len - 4, data + 4);
          break;
        }
      }
    }

    if (dev != NULL) {
      dev->peerRssi = esp_now_info->rx_ctrl->rssi;
      dev->lastSeen = esp_log_timestamp();
      char *name = bufAs0TermString(data + 4, len - 4);
      ESP_LOGD(TAG, "PAIR " MACSTR ": %s", MAC2STR(esp_now_info->src_addr), name);
      strtok(name, PAIR_DELIM);
      char *hub = strtok(NULL, PAIR_DELIM);
      if (!hub || strcmp(hub, MQTT_TOPIC)) {
        // Pairing request was meant for a different network
        free(name);
        return;
      }
      char *info = strtok(NULL, "");
      if (info) {
        if (dev->info) free(dev->info);
        dev->info = bufAs0TermString(info, strlen(info));
      }
      memcpy(dev->mac, esp_now_info->src_addr, sizeof(MACAddr));
      strncpy(dev->name, name, sizeof(device_name_t));
      free(name);

      if (!esp_now_is_peer_exist(esp_now_info->src_addr)) {
        esp_now_peer_info_t peer;
        memset(&peer, 0, sizeof(peer));
        peer.ifidx = WIFI_IF_STA;
        memcpy(&peer.peer_addr, esp_now_info->src_addr, sizeof(MACAddr));

        esp_now_add_peer(&peer);
      }

      ESP_LOGD(TAG, "Send " MACSTR " PACK", MAC2STR(esp_now_info->src_addr));
      esp_now_send(esp_now_info->src_addr, (const uint8_t *)PACK, sizeof(PACK));
      hubStatusChanged = true;
      // std::string json;
      // {
      //   Locked device(devices);
      //   json = hubStatusJson(device);
      // }
      // mqtt_client_publish(mqtt_client, MQTT_TOPIC, json.c_str(), 0, 1, RETAIN);
    } else {
      ESP_LOGE(TAG, "No device space for pairing %s " MACSTR, data + 4, MAC2STR(esp_now_info->src_addr));
      sendNACK(esp_now_info->src_addr);
    }
  } else if ((*(const uint32_t *)data) == NACK[0]) {
    if (dev != NULL) {
      dev->lastSeen = 0; // Mark for unpairing
      //unpairDevice(dev, "NACK");
    } else {
      ESP_LOGI(TAG, "NACK from unknown device " MACSTR, MAC2STR(esp_now_info->src_addr));
    }
  } else if (*data == '{') {
    // Some JSON we need to forward to the MQTT broker
    if (dev != NULL) {
      dev->peerRssi = esp_now_info->rx_ctrl->rssi;
      dev->lastSeen = esp_log_timestamp();

      std::string topic = MQTT_TOPIC;
      topic += "/";
      topic += dev->name;

      // We add meta data to the payload
      auto payloadData = std::string((const char *)data, len);
      cJSON *payload = cJSON_Parse(payloadData.c_str());
      if (payload) {
        cJSON *meta = cJSON_Parse(metaJson(dev).c_str());
        cJSON_AddItemToObject(payload, "meta", meta);
        const auto jsonBuf = cJSON_PrintUnformatted(payload);
        mqtt_client_publish(mqtt_client, topic.c_str(), jsonBuf, 0, 1, RETAIN);
        free(jsonBuf);
        cJSON_Delete(payload);
        hubStatusChanged = true;
        // std::string json;
        // {
        //   Locked device(devices);
        //   json = hubStatusJson(device);
        // }
        // mqtt_client_publish(mqtt_client, MQTT_TOPIC, json.c_str(), 0, 1, RETAIN);
      } else {
        ESP_LOGW(TAG, "Failed to parse JSON: %*.s", len, data);
      }
    } else {
      ESP_LOGI(TAG, "NACK data from unknown device " MACSTR " %.*s", MAC2STR(esp_now_info->src_addr), len, data);
      sendNACK(esp_now_info->src_addr);
    }
  } else {
    ESP_LOGI(TAG, "Unknown message from " MACSTR " %s", MAC2STR(esp_now_info->src_addr), data);
  }

  if (dev != NULL) {
    if (dev->pending.length()) {
      ESP_LOGD(TAG, "Send " MACSTR " pending (recv)", MAC2STR(esp_now_info->src_addr));
      esp_now_send(dev->mac, (const uint8_t *)dev->pending.c_str(), dev->pending.length() + 1);
    }
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

class ConfigPortal : public HttpGetHandler {
 protected:
  bool withClose;
  bool startsWith(const char *search, const char *match) {
    return strncmp(search, match, strlen(match)) == 0;
  }

  static void unencode(char *buf, const char *src, int size) {
    while (*src && size) {
      if (*src == '%') {
        auto msn = hexValue(src[1]);
        auto lsn = hexValue(src[2]);
        src += 3;
        *buf++ = (char)(msn * 16 + lsn);
      } else {
        *buf++ = *src++;
        size--;
      }
    }
    *buf = 0;
  }

 public:
  wifi_sta_config_t &sta;
  char *mqtt_server;
  bool done;

  ConfigPortal(wifi_sta_config_t &sta, char *mqtt_server, bool withClose) : withClose(withClose), sta(sta), mqtt_server(mqtt_server) {
    done = false;
  }

  esp_err_t getHandler(httpd_req_t *req) {
    if (startsWith(req->uri, "/close")) {
      if (withClose) done = true;
      else {
        httpd_resp_set_status(req, "307 Temporary Redirect");
        httpd_resp_set_hdr(req, "Location", "/");
        httpd_resp_send(req, NULL, 0); // No response body needed
        esp_restart();
      }
    } else if (startsWith(req->uri, "/set-wifi/")) {
      char input_param[sizeof(req->uri)];
      strncpy(input_param, req->uri + 10, sizeof(req->uri));
      strtok(input_param, "-");
      const char *in_pwd = strtok(NULL, "-");
      const char *in_mqtt = strtok(NULL, "-");

      unencode((char *)sta.ssid, input_param, sizeof(sta.ssid));
      if (in_pwd) unencode((char *)sta.password, in_pwd, sizeof(sta.password));
      if (in_mqtt) unencode(mqtt_server, in_mqtt, 64);
      if (strlen((const char *)sta.ssid) && in_pwd && strlen((const char *)sta.password) && in_mqtt && strlen(mqtt_server)) {
        nvs_handle_t nvs_handle;
        if (nvs_open("storage", NVS_READWRITE, &nvs_handle) == ESP_OK) {
          ESP_LOGI(TAG, "Confirmed config ssid %s mqtt %s", sta.ssid, mqtt_server);
          nvs_set_str(nvs_handle, "ssid", (const char *)sta.ssid);
          nvs_set_str(nvs_handle, "wifipwd", (const char *)sta.password);
          nvs_set_str(nvs_handle, "mqtt", mqtt_server);
          nvs_close(nvs_handle);
        }
        if (withClose) done = true;
        else {
          httpd_resp_set_status(req, "307 Temporary Redirect");
          httpd_resp_set_hdr(req, "Location", "/");
          httpd_resp_send(req, NULL, 0); // No response body needed
          // Delay to flush response
          vTaskDelay(100 / portTICK_PERIOD_MS);
          esp_restart();
        }
      }
    } else if (startsWith(req->uri, "/unpair/")) {
      MACAddr mac;
      macFromHex12(req->uri + 8, mac, false);
      Locked device(devices);
      auto dev = findDeviceMac(device, mac);
      if (dev != NULL) {
        sendNACK(mac);
        dev->lastSeen = 0; // Mark for unpairing
        //unpairDevice(dev, "user request");
        httpd_resp_set_status(req, "302 Temporary Redirect");
        // Redirect to the "/" anyGet directory
        httpd_resp_set_hdr(req, "Location", "/");
        // iOS requires content in the response to detect a captive portal, simply redirecting is not sufficient.
        httpd_resp_send(req, "Redirect", HTTPD_RESP_USE_STRLEN);
      }
    } else if (startsWith(req->uri, "/otaupdate/")) {
      MACAddr mac;
      macFromHex12(req->uri + 11, mac, false);
      Locked device(devices);
      auto dev = findDeviceMac(device, mac);
      if (dev != NULL) {
        std::string otaJson = "{\"ota\":{\"url\":\"" OTA_ROOT_URI "\",\"ssid\":\""
              + std::string((const char *)sta.ssid)
              + "\",\"pwd\":\""
              + std::string((const char *)sta.password)
              + "\"}}";
        mergeAndSendPending(dev, otaJson.c_str());

        httpd_resp_set_status(req, "302 Temporary Redirect");
        // Redirect to the "/" anyGet directory
        httpd_resp_set_hdr(req, "Location", "/");
        // iOS requires content in the response to detect a captive portal, simply redirecting is not sufficient.
        httpd_resp_send(req, "Redirect", HTTPD_RESP_USE_STRLEN);
      }
    } else if (strcmp(req->uri,"") && strcmp(req->uri,"/")) {
      ESP_LOGI(TAG, "Http unknown URL%s", req->uri);
      httpd_resp_set_status(req, "404 Not found");
      httpd_resp_send(req, "404 Not found", HTTPD_RESP_USE_STRLEN);
      return ESP_OK;
    }

    // Send back the current status
    httpd_resp_set_type(req, "text/html");

    auto now = esp_log_timestamp();
    std::stringstream html;
    html << "<!DOCTYPE html>"
            "<html>"
            "<head>"
            "<meta charset=\"UTF-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>" << hostname << "</title>"
            "<style>* { font-family: sans-serif; } button { display: block; margin: 0.5em; }</style>"
            "<script>"

            MULTILINE_STRING(
            function ota_upload(elt) {
              elt.disabled = true;
              const input = document.getElementById('firmware');
              if (!input.files.length || !(input.files[0] instanceof Blob)) {
                alert('Please select a file.');
                return;
              }

              const file = input.files[0];
              const xhr = new XMLHttpRequest();

              // Optional: Show progress in the console; replace with UI update as needed
              xhr.upload.onprogress = function(event) {
                if (event.lengthComputable) {
                  const percentComplete = (event.loaded / event.total) * 100;
                  elt.textContent = (`${percentComplete.toFixed(2)}% complete`);
                } else {
                  elt.textContent = (`Uploaded ${event.loaded} bytes`);
                }
              };

              xhr.onload = function() {
                elt.textContent = 'Upload\n\n' + xhr.statusText;
                elt.disabled = false;
              };

              xhr.open('POST', '/ota', true);
              xhr.send(file);
            }
            )

            "</script>"
                  "</head>"
            "<body>"
            "<h1>" << hostname << " (" << hub_ip << ")</h1>"
            "<h2>Devcies</h1>"
            "<table>"
            "<tr><th>Unpair</th><th>Name</th><th>Model</th><th>Last seen</th><th>Rssi</th><th>Build</th><th>Update</th></tr>";

    {
      Locked device(devices);
      for (int i = 0; i < ESP_NOW_MAX_TOTAL_PEER_NUM; i++) {
        if (device[i].name[0]) {
          char mac[20];
          sprintf(mac, "%02x%02x%02x%02x%02x%02x", MAC2STR(device[i].mac));
          html << "<tr>"
            "<td><button onclick='window.location.href = \"/unpair/" << mac << "\"'>&#128465;</button></td>"
            "<td>" << device[i].name << "</td>"
            "<td><script>document.currentScript.replaceWith(" << (device[i].info ? device[i].info : "{ model:'?'}") << ".model)</script>" << "</td>"
            "<td><script>document.currentScript.replaceWith(new Date(Date.now()-" << (signed)(now - device[i].lastSeen) << ").toLocaleString())</script></td>"
            "<td>" << device[i].peerRssi << "</td>"
            "<td><script>document.currentScript.replaceWith(" << (device[i].info ? device[i].info : "{ build:'?'}") << ".build)</script>" << "</td>"
            "<td><button onclick='window.location.href = \"/otaupdate/" << mac << "\"'>&#128428;</button></td>"
            "</tr>";
        }
      }
    }

    html << "</table>"
            "<h2>Config</h1>"
            "<table>"
            "<tr><td>WiFi SSID</td><td><input id='ssid' value='" << sta.ssid << "'></td></tr>"
            "<tr><td>WiFi password</td><td><input id='pwd' value='" << sta.password << "'></td></tr>"
            "<tr><td>MQTT server</td><td><input id='mqtt' value='" << mqtt_server << "'></td></tr>"
            "</table>"
            "<button onclick='window.location.href = \"/set-wifi/\"+encodeURIComponent(\"ssid,pwd,mqtt\".split(\",\").map(id => document.getElementById(id).value).join(\"-\"))'>Save</button>"
            "<button onclick='window.location.href = \"/close/\"'>"<< (withClose ? "Close" : "Restart") << "</button>"
            "<h2>OTA Update</h2>"
            "<div>"
            "  <input type='file' id='firmware'>"
            "  <button onclick='ota_upload(this)'>Update</button>"
            "</div>"
            "<div>Current: " BUILD_TIMESTAMP "</div>"
            "</body></html>";

    httpd_resp_send(req, html.str().c_str(), HTTPD_RESP_USE_STRLEN);

    // if (startsWith(req->uri, "/close")) {
    //   if (!withClose) esp_restart();
    // }
    return ESP_OK;
  }
};

extern "C" void app_main(void) {
  esp_log_level_set(TAG, ESP_LOG_INFO);
//  esp_log_level_set("*", ESP_LOG_INFO);

  // Initialize NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  static device_table_t _devices;
  devices = new SerializedStatic(_devices);

  ESP_LOGI(TAG, "Startup. Build: " BUILD_TIMESTAMP);

  // Initialize TCP/IP stack and WiFi
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  GPIO::pinMode(IO_LED_R, OUTPUT);
  GPIO::pinMode(IO_LED_G, OUTPUT);
  GPIO::pinMode(IO_LED_B, OUTPUT);
  GPIO::pinMode(IO_BUTTON, INPUT);

  // If no config, start the captive portal
  size_t len;

  nvs_handle_t nvs_handle = -1;
  char mqtt_uri[64] = {0};
  if (nvs_open("storage", NVS_READWRITE, &nvs_handle) != ESP_OK
    || ((len = sizeof(wifi_config.sta.ssid)), (nvs_get_str(nvs_handle, "ssid", (char *)wifi_config.sta.ssid, &len) != ESP_OK))
    || ((len = sizeof(wifi_config.sta.password)), (nvs_get_str(nvs_handle, "wifipwd", (char *)wifi_config.sta.password, &len) != ESP_OK))
    || ((len = sizeof(mqtt_uri)), (nvs_get_str(nvs_handle, "mqtt", mqtt_uri, &len) != ESP_OK))) {
    if (nvs_handle != -1) nvs_close(nvs_handle);

  no_net_start_captive_portal:
    ESP_LOGI(TAG, "No wifi credentials found");
    // Start captive portal which sets nvs keys
    mqtt_uri[sizeof(mqtt_uri) - 1] = 0;
    wifi_config.sta.ssid[sizeof(wifi_config.sta.ssid) - 1] = 0;
    wifi_config.sta.password[sizeof(wifi_config.sta.password) - 1] = 0;

    auto portal = new ConfigPortal(wifi_config.sta, mqtt_uri, true);
    start_captive_portal(portal, "FreeHouse-HUB");

    bool led = true;
    while (true) {
      led = !led;
      // Flashing magenta - captive portal is running
      GPIO::digitalWrite(IO_LED_B, led);
      GPIO::digitalWrite(IO_LED_R, led);
      GPIO::digitalWrite(IO_LED_G, 0);

      vTaskDelay(1000 / portTICK_PERIOD_MS);
      if (portal->done) {
        GPIO::digitalWrite(IO_LED_B, 0);
        GPIO::digitalWrite(IO_LED_R, 0);
        esp_restart();
      }
    }
  }

  if (nvs_handle != -1) nvs_close(nvs_handle);

  esp_read_mac(gateway_mac, ESP_MAC_WIFI_STA);

  esp_netif_t *netif = esp_netif_create_default_wifi_sta();  // Create default STA interface
  unsigned int mac_hash = 0;
  for (int i = 0; i < sizeof(gateway_mac); i++) {
    mac_hash += gateway_mac[i];
  }
  snprintf(hostname, sizeof(hostname), "freehouse-hub-%03u", mac_hash % 1000);
  esp_netif_set_hostname(netif, hostname);  // Set hostname for the STA interface

  wifi_event_group = xEventGroupCreate();

  // Register event handler
  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  // wifi_country_t country = {
  //   .cc = "EU",           // Country code for Europe
  //   .schan = 1,           // Start channel must be 1
  //   .nchan = 13,          // Number of channels allowed in EU (channels 1 to 13)
  //   .policy = WIFI_COUNTRY_POLICY_MANUAL  // Use manual policy to enforce these settings
  // };
  // esp_wifi_set_country(&country);

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

  // Start WiFi
  ESP_ERROR_CHECK(esp_wifi_start());

  // Yellow LED - connecting
  GPIO::digitalWrite(IO_LED_R, 1);
  GPIO::digitalWrite(IO_LED_G, 1);
  ESP_LOGI(TAG, "Connecting to WiFi %s", wifi_config.sta.ssid);
  if (xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, 30000 / portTICK_PERIOD_MS) & WIFI_CONNECTED_BIT) {
    ESP_LOGI(TAG, "Connected to WiFi %s", wifi_config.sta.ssid);
  } else {
    ESP_LOGE(TAG, "Failed to connect to WiFi %s", wifi_config.sta.ssid);
    goto no_net_start_captive_portal;
  }

  // Get MAC address
  ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, gateway_mac));

  uint8_t primary_channel;
  wifi_second_chan_t secondary_channel = WIFI_SECOND_CHAN_NONE;
  esp_err_t result = esp_wifi_get_channel(&primary_channel, &secondary_channel);

  if (result != ESP_OK) {
    // Red LED - no network
    GPIO::digitalWrite(IO_LED_R, 1);
    GPIO::digitalWrite(IO_LED_G, 0);
    ESP_LOGE(TAG, "Failed to get channel: %d", result);
    return;
  }

  esp_netif_ip_info_t ip_info;
  ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_get_ip_info(netif, &ip_info));
  snprintf(hub_ip, sizeof(hub_ip), IPSTR, IP2STR(&ip_info.ip));

  // Green LED - connected
  GPIO::digitalWrite(IO_LED_R, 0);
  GPIO::digitalWrite(IO_LED_G, 1);
  ESP_LOGI(TAG,
           "WiFi connected %s: Primary channel: %d, Secondary channel: %d, IP %s, MAC " MACSTR,
           wifi_config.sta.ssid,
           primary_channel,
           secondary_channel,
           hub_ip,
           MAC2STR(gateway_mac));

  // Initialize ESP-NOW
  ESP_ERROR_CHECK(esp_now_init());
  ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_recv_cb));
  ESP_ERROR_CHECK(esp_now_register_send_cb(espnow_send_cb));

  // Initialize MQTT
  std::string mqtt = "mqtt://";
  mqtt += mqtt_uri;
  esp_mqtt_client_config_t mqtt_cfg = {
      .broker = {.address = {.uri = mqtt.c_str()}},
      .network = {.disable_auto_reconnect = false},
      .buffer = { .size = MQTT_BUFFER_SIZE, .out_size = MQTT_BUFFER_SIZE },
      .outbox = { .limit = MQTT_BUFFER_SIZE }
    };

  mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
  ESP_ERROR_CHECK_WITHOUT_ABORT(esp_mqtt_client_register_event(mqtt_client, (esp_mqtt_event_id_t)ESP_EVENT_ANY_ID, mqtt_event_handler, NULL));
  ESP_ERROR_CHECK_WITHOUT_ABORT(esp_mqtt_client_start(mqtt_client));

  // Normal mode - no captive portal
  auto portal = new ConfigPortal(wifi_config.sta, mqtt_uri, false);
  start_web_server(portal);

  int pressed = 0;
  // LED off: running
  GPIO::digitalWrite(IO_LED_G, 0);


  // static heap_trace_record_t trace_record[10]; // Must be in internal RAM
  // heap_trace_init_standalone(trace_record, 10);
  // heap_trace_start(HEAP_TRACE_LEAKS);

  uint32_t lastFree = 0;
  while (1) {
    auto button = GPIO::digitalRead(IO_BUTTON);
    GPIO::digitalWrite(IO_LED_B, !button);
    if (button == 0) {
      // Check for BOOT button, clear the nvs and restart
      if (++pressed == 10) {
        nvs_open("storage", NVS_READWRITE, &nvs_handle);
        nvs_erase_key(nvs_handle, "ssid");
        nvs_erase_key(nvs_handle, "wifipwd");
        nvs_erase_key(nvs_handle, "mqtt");
        nvs_close(nvs_handle);
        GPIO::digitalWrite(IO_LED_B, 0);
        esp_restart();
      }
      GPIO::digitalWrite(IO_LED_B, pressed & 1);
      vTaskDelay(250 / portTICK_PERIOD_MS);
    } else {
      pressed = 0;
      vTaskDelay(1000 / portTICK_PERIOD_MS);
      auto thisFree = esp_get_free_heap_size();
      if (lastFree != thisFree) {
        lastFree = thisFree;
        ESP_LOGV(TAG,"Free heap %lu", thisFree);
      }
      // heap_trace_dump();
    }

    std::string json;
    {
      Locked device(devices);
      auto now = esp_log_timestamp();
      for (int i = 0; i < ESP_NOW_MAX_TOTAL_PEER_NUM; i++) {
        auto dev = &device[i];
        if (dev->name[0] && (dev->lastSeen == 0 || (signed)(now - dev->lastSeen) > DEVICE_TIMEOUT)) {
          unpairDevice(dev, "time out");
          hubStatusChanged = true;
        }
      }
      if (hubStatusChanged) {
        json = hubStatusJson(device);
        hubStatusChanged = false;
      }
    }
    if (json.length() > 0)
      mqtt_client_publish(mqtt_client, MQTT_TOPIC, json.c_str(), 0, 1, 0);
  }
}
