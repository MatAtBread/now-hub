#ifndef RWL_H
#define RWL_H

#include "esp_log.h"

#define MAX_BACKTRACE_DEPTH 6
#define BACK_TRACE_SKIP     3

extern "C" const char* TAG;

template <typename T>
class Locked;

template <typename T>
class WriteLocked;

typedef struct {
  const void* pc;
  const void* sp;
  const void* frames[MAX_BACKTRACE_DEPTH + 1];
} backtrace_frame_t;

static void capture_backtrace(backtrace_frame_t& saved_frame) {
#ifdef MAX_BACKTRACE_DEPTH
  uint32_t sp_val, pc_val, fp_val;

  // Load stack pointer & program counter
  __asm__ volatile("mv %0, sp" : "=r"(sp_val));
  __asm__ volatile("auipc %0, 0" : "=r"(pc_val));
  __asm__ volatile("mv %0, s0" : "=r"(fp_val));

  // esp_backtrace_get_start(&saved_frame.pc, &saved_frame.sp, &saved_frame.next_pc);
  saved_frame.sp = (const void*)sp_val;
  saved_frame.pc = (const void*)pc_val;  // Get the first frame of the current stack backtrace
  auto fp = (const void**)fp_val;
  memset(saved_frame.frames, 0, sizeof(saved_frame.frames));
  for (int i = 0; i < MAX_BACKTRACE_DEPTH + BACK_TRACE_SKIP && fp; i++) {
    // ESP_LOGI(TAG,"%p:  %p %p %p %p %p", fp, fp[-2], fp[-1], fp[-0], fp[1], fp[2]);
    if (i >= BACK_TRACE_SKIP)
      saved_frame.frames[i - BACK_TRACE_SKIP] = fp[-1];
    fp = (const void**)fp[-2];
    if (!fp || (((uint32_t)fp) & 0xFF000001) != 0x3f000000)
      break;
  }
#endif
}

static void print_backtrace(backtrace_frame_t& saved_frame) {
#ifdef MAX_BACKTRACE_DEPTH
  ESP_LOGI(TAG, "PC: %p\tSP: %p", (void*)saved_frame.pc, (void*)saved_frame.sp);
  for (int i = 0; i < MAX_BACKTRACE_DEPTH; i++) {
    ESP_LOGI(TAG, " at PC: %p", saved_frame.frames[i]);
  }
#endif
}

static void print_current_backtrace() {
  backtrace_frame_t saved_frame;
  capture_backtrace(saved_frame);
  print_backtrace(saved_frame);
}

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
  friend class WriteLocked<T>;

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