#ifndef RWL_H
#define RWL_H

#include "esp_log.h"

#define MAX_BACKTRACE_DEPTH 6
#define BACK_TRACE_SKIP     3

extern "C" const char* TAG;

typedef struct {
  const void* pc;
  const void* sp;
  const void* frames[MAX_BACKTRACE_DEPTH + 1];
} backtrace_frame_t;

void capture_backtrace(backtrace_frame_t& saved_frame);
void print_backtrace(backtrace_frame_t& saved_frame);
void print_current_backtrace();

template <typename T>
class Locked;

template <typename T>
class SerializedStatic {
 private:
  SerializedStatic(SerializedStatic& l) {
    // assert(!"Copy constructor not allowed");
  }

 protected:
  SemaphoreHandle_t xRecursiveMutex;
  T& obj;
  char ownerTaskName[64];
  TaskHandle_t ownerTask;
#ifdef MAX_BACKTRACE_DEPTH
  backtrace_frame_t saved_frame;
#endif
  void capture_owner(void) {
    strncpy(ownerTaskName, pcTaskGetName(ownerTask = xTaskGetCurrentTaskHandle()), 64);
    capture_backtrace(saved_frame);
  }

  void print_owner(void) {
    ESP_LOGI(TAG, "Backtrace captured for %s (currently %s)", ownerTaskName, pcTaskGetName(xTaskGetCurrentTaskHandle()));
    print_backtrace(saved_frame);
  }

  void clear_owner() {
    ownerTask = NULL;
    // strncpy(ownerTaskName, "n/a", 64);
  }

  friend class Locked<T>;

 public:
  SerializedStatic(T& obj) : obj(obj) {
    xRecursiveMutex = xSemaphoreCreateRecursiveMutex();
    ESP_LOGI(TAG, "Test backtrace....");
    print_current_backtrace();
  }
  ~SerializedStatic() {
    vSemaphoreDelete(xRecursiveMutex);
  }
};

template <typename T>
class Locked {
 protected:
  SerializedStatic<T>* l;
  int taken;  // 0: Not yet accessed. 1: Taken. -1: Failed to take
  uint32_t lockedAt;

 public:
  Locked(SerializedStatic<T>* l) : l(l) {
    taken = 0;
  }
  ~Locked() {
    if (taken != 0) {
      u_int32_t waited = esp_log_timestamp() - lockedAt;
      if (waited > 1000) {
        ESP_LOGE(TAG, "Long resource lock in %s ~ %p finally released after %lums (taken? %d) Allocated by: ", pcTaskGetName(xTaskGetCurrentTaskHandle()), this, waited, taken);
        l->print_owner();
        ESP_LOGW(TAG,"Released at:");
        print_current_backtrace();
      }
      if (taken < 0) {
        ESP_LOGW(TAG, "~Locked(%s ~ %p) not taken", pcTaskGetName(xTaskGetCurrentTaskHandle()), this);
      } else {
        if (xSemaphoreGiveRecursive(l->xRecursiveMutex) != pdTRUE) {
          ESP_LOGW(TAG, "~Locked(%s ~ %p) failed", pcTaskGetName(xTaskGetCurrentTaskHandle()), this);
        }
        l->clear_owner();
      }
    }  // else lock unused
  }
  operator T&() {
    if (taken == 0) {
      if (xSemaphoreTakeRecursive(l->xRecursiveMutex, 5000 / portTICK_PERIOD_MS) == pdTRUE) {
        taken = 1;
      } else {
        taken = -1;
      }

      lockedAt = esp_log_timestamp();
      if (taken != 1) {
        ESP_LOGW(TAG, "Locked(%s ~ %p) Cannot lock resource (taken? %d). Currently held by:", pcTaskGetName(xTaskGetCurrentTaskHandle()), this, taken);
        l->print_owner();
        ESP_LOGW(TAG,"Attempted acquisiton by:");
        print_current_backtrace();
      } else {
        l->capture_owner();
      }
    }
    return l->obj;
  }
};

#endif  // RWL_H