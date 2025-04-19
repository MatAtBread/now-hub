//#define CONFIG_BIND_USE_IRAM_HEAP 1 -- THIS DOESN'T CURRENTLY WORK

#ifdef __riscv

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"

#define CONFIG_MAX_BOUND_METHODS 64 /* Allow for 64 bound functions */
extern "C" const char *TAG;

#define CUSTOM_HEAP_SIZE 8 * CONFIG_MAX_BOUND_METHODS
static uint32_t IRAM_ATTR boundPreambles[CUSTOM_HEAP_SIZE];

#ifdef CONFIG_BIND_USE_IRAM_HEAP
#include "esp_heap_caps.h"
#include "esp_heap_caps_init.h"
#else
static uint8_t usedPreamble[CONFIG_MAX_BOUND_METHODS] = {0};
#endif

static inline uint32_t lui(uint32_t n) {
  return (n & 0xFFFFF000) + ((n & 0x800) << 1);
}

void *_bind(void *self, void *f) {
  if ((uint32_t)f < 1024UL) {
    // Index into the vtable
    auto vtab = ((uint32_t **)self)[0];
    f = (void *)(vtab[((uint32_t)f - 1) / sizeof(uint32_t)]);
  }

  uint32_t ip[] = {
    // 0x00100073,  // EBREAK
    // Shuffle up the parameters a0-a3 by one reg
    0x86b28736,  // c.mv a4, a3 := 0x8736, c.mv a3, a2 := 0x86b2
    0x85aa862e,  // c.mv a2, a1 := 0x862e, c.mv a1, a0 := 0x85aa
    // # Load 32-bit constant 0x12345678 into a0
    0x00000537 | lui((uint32_t)self),                    // 0x{12345}537  # lui a0, 0x12345        # Load upper 20 bits
    0x00050513 | (((uint32_t)self & 0x00000FFF) << 20),  // 0x{678}50513  # addi a0, a0, 0x678     # Add lower 12 bits
    // # Jump to 32-bit address 0xABCDEF00
    0x000002B7 | lui((uint32_t)f & 0xFFFFF000),       // 0x{ABCDE}2B7  # lui t0, 0xABCDE        # Load upper 20 bits of jump address into t0
    0x00028293 | (((uint32_t)f & 0x00000FFF) << 20),  // 0x{F00}28293  # addi t0, t0, 0xF00     # Add lower 12 bits of jump address
    0x00028067                                        // 0x00028067    # jr t0                  # Jump to address in t0
  };


#ifdef CONFIG_BIND_USE_IRAM_HEAP
  size_t heap_size = heap_caps_get_total_size(MALLOC_CAP_32BIT | MALLOC_CAP_EXEC);
  ESP_LOGW(TAG, "Binding %lx with this %lx, heap size: %u", (uint32_t)f, (uint32_t)self, heap_size);
  if (heap_size == 0) {
    ESP_LOGW(TAG, "Initialize IRAM heap");
    uint32_t caps[3] = {MALLOC_CAP_EXEC, MALLOC_CAP_32BIT, 0};
    if (heap_caps_add_region_with_caps(caps, (int)boundPreambles, (int)(boundPreambles + CUSTOM_HEAP_SIZE)) != ESP_OK) {
      ESP_LOGE(TAG, "Failed to initialise bound function heap");
      return 0;
    }
  }
  heap_caps_print_heap_info(MALLOC_CAP_32BIT | MALLOC_CAP_EXEC);

  // Allocate executable space for the sizeof(ip) preamble instructions that load "this" into A0 and call the target function
  uint32_t *binding = (uint32_t *)heap_caps_malloc(sizeof(ip), MALLOC_CAP_EXEC | MALLOC_CAP_32BIT);
#else
  uint32_t *binding = 0;
  for (int i = 0; i < sizeof(usedPreamble) / sizeof(usedPreamble[0]); i++) {
    if (!usedPreamble[i]) {
      usedPreamble[i] = 1;
      binding = &boundPreambles[i * sizeof(ip) / sizeof(ip[0])];
      break;
    }
  }
#endif
  if (!binding) {
    ESP_LOGW(TAG, "No IRAM for function binding preamble. CONFIG_MAX_BOUND_METHODS = %d", CONFIG_MAX_BOUND_METHODS);
  } else {
    ESP_LOGI(TAG, "Binding function 0x%08lx() @0x%08lx to object 0x%08lx.", (uint32_t)f, (uint32_t)binding, (uint32_t)self);
    memcpy(binding, ip, sizeof(ip));
    //__asm__("fence.i");
  }
  return binding;
}

template<typename T>
void unbind(T f) {
#ifdef CONFIG_BIND_USE_IRAM_HEAP
  heap_caps_free(f);
#else
  auto i = (uint32_t *)f - boundPreambles;
  usedPreamble[i] = 0;
#endif
}

#ifdef CONFIG_ESP_SYSTEM_MEMPROT_FEATURE
#warning "C++ function bind() and unbind() is incompatible with CONFIG_ESP_SYSTEM_MEMPROT_FEATURE"
#endif

#else
#error "C++ function bind() and unbind() require a RISC-V architecture"
#endif
