#ifndef WIFI_CAPTIVEPORTAL_H
#define WIFI_CAPTIVEPORTAL_H

#include "esp_http_server.h"

class HttpGetHandler {
  public:
    virtual esp_err_t getHandler(httpd_req_t *req) = 0;
};

void start_captive_portal(HttpGetHandler *handler, const char *ssid);
void start_web_server(HttpGetHandler *_handler);
#endif