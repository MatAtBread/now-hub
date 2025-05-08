#ifndef RWL_H
#define RWL_H

#include "esp_log.h"
#include "string.h"
#include "rwl.hpp"

#define MAX_BACKTRACE_DEPTH 6
#define BACK_TRACE_SKIP     0

extern "C" const char* TAG;

typedef struct {
  const void* pc;
  const void* sp;
  const void* frames[MAX_BACKTRACE_DEPTH + 1];
} backtrace_frame_t;

void capture_backtrace(backtrace_frame_t& saved_frame) {
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

void print_backtrace(backtrace_frame_t& saved_frame) {
#ifdef MAX_BACKTRACE_DEPTH
  ESP_LOGI(TAG, "PC: %p\tSP: %p", (void*)saved_frame.pc, (void*)saved_frame.sp);
  for (int i = 0; i < MAX_BACKTRACE_DEPTH; i++) {
    ESP_LOGI(TAG, " at PC: %p", saved_frame.frames[i]);
  }
#endif
}

void print_current_backtrace() {
  backtrace_frame_t saved_frame;
  capture_backtrace(saved_frame);
  print_backtrace(saved_frame);
}

#endif  // RWL_H