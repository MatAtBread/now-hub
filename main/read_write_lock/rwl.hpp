#ifndef RWL_H
#define RWL_H

#include "esp_log.h"

#define MAX_BACKTRACE_DEPTH 6

#ifdef MAX_BACKTRACE_DEPTH
#include "esp_debug_helpers.h"
#endif

extern "C" const char* TAG;


template <typename T>
class Locked;

template <typename T>
class WriteLocked;

template <typename T>
class SerializedStatic {
 private:
  SerializedStatic(SerializedStatic& l) {
    // assert(!"Copy constructor not allowed");
  }

 protected:
  SemaphoreHandle_t xRecursiveMutex;
  T& obj;
  char currentOwningTask[64];
#ifdef MAX_BACKTRACE_DEPTH
  esp_backtrace_frame_t saved_frame;
#endif
  void capture_backtrace(void) {
    strncpy(currentOwningTask, pcTaskGetName(xTaskGetCurrentTaskHandle()), 64);
#ifdef MAX_BACKTRACE_DEPTH
    uint32_t sp_val, pc_val, fp_val;

    // Load stack pointer & program counter
    __asm__ volatile ("mv %0, sp" : "=r"(sp_val));
    __asm__ volatile ("auipc %0, 0" : "=r"(pc_val));
    __asm__ volatile ("mv %0, s0" : "=r"(fp_val));

    //esp_backtrace_get_start(&saved_frame.pc, &saved_frame.sp, &saved_frame.next_pc);
    saved_frame.sp = sp_val;
    saved_frame.pc = pc_val;    // Get the first frame of the current stack backtrace
    saved_frame.next_pc = 0;
    saved_frame.exc_frame = (const void *)fp_val;
#endif
}

  void print_saved_backtrace(void) {
    ESP_LOGI(TAG,"Backtrace captured for %s (currently %s)", currentOwningTask, pcTaskGetName(xTaskGetCurrentTaskHandle()));
    #ifdef MAX_BACKTRACE_DEPTH
    ESP_LOGI(TAG, "PC: %p\tFP: %p\tSP: %p [%ld]", (void *)saved_frame.pc, saved_frame.exc_frame, (void *)saved_frame.sp, (int32_t)saved_frame.exc_frame - (int32_t)saved_frame.sp);
    const void **fp = (const void **)saved_frame.exc_frame;
    for (int i = 0; i < MAX_BACKTRACE_DEPTH && fp && (((uint32_t)fp) & 3) == 0; i++) {
      ESP_LOGI(TAG, " at PC: %p", fp[-1]);
      fp = (const void **)fp[-2];
    }
    // for (int i = 0; i < MAX_BACKTRACE_DEPTH; i++) {
    //   esp_backtrace_get_next_frame(&saved_frame);
    //   esp_backtrace_print_from_frame(1, &saved_frame, false);
    // }
    #endif
  }

  void clear_backtrace() {
    strncpy(currentOwningTask, "n/a", 64);
  }

  friend class Locked<T>;
  friend class WriteLocked<T>;

 public:
  SerializedStatic(T& obj) : obj(obj) {
    xRecursiveMutex = xSemaphoreCreateRecursiveMutex();
    ESP_LOGI(TAG, "Test backtrace....");
    capture_backtrace();
    print_saved_backtrace();
  }
  ~SerializedStatic() {
    vSemaphoreDelete(xRecursiveMutex);
  }
};

template <typename T>
class Locked {
 protected:
  SerializedStatic<T>* l;
  bool taken;
  uint32_t lockedAt;

 public:
  Locked(SerializedStatic<T>* l) : l(l) {
    lockedAt = esp_log_timestamp();
    taken = xSemaphoreTakeRecursive(l->xRecursiveMutex, 5000 / portTICK_PERIOD_MS) == pdTRUE;
    if (!taken) {
      ESP_LOGW(TAG, "Locked(%s ~ %p) Cannot lock resource", pcTaskGetName(xTaskGetCurrentTaskHandle()), this);
      l->print_saved_backtrace();
    } else {
      l->capture_backtrace();
    }
  }
  ~Locked() {
    if (esp_log_timestamp() - lockedAt > 500) {
      ESP_LOGW(TAG, "Long resource lock in %s ~ %p", pcTaskGetName(xTaskGetCurrentTaskHandle()), this);
      l->print_saved_backtrace();
    }
    if (!taken) {
      ESP_LOGW(TAG, "~Locked(%s ~ %p) not taken", pcTaskGetName(xTaskGetCurrentTaskHandle()), this);
    } else {
      if (xSemaphoreGiveRecursive(l->xRecursiveMutex) != pdTRUE) {
        ESP_LOGW(TAG, "~Locked(%s ~ %p) failed", pcTaskGetName(xTaskGetCurrentTaskHandle()), this);
      }
      l->clear_backtrace();
    }
  }
  operator T&() { return l->obj; }
};

#endif  // RWL_H