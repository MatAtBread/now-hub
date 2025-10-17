#include "esp_log.h"
#include "driver/gpio.h"
#include "esp_adc/adc_oneshot.h"
#include "hal/gpio_types.h"

#include "gpio.hpp"

extern "C" const char* TAG;

static void adc_calibration_deinit(adc_cali_handle_t handle);
static bool adc_calibration_init(adc_unit_t unit, adc_channel_t channel, adc_atten_t atten, adc_cali_handle_t *out_handle);

static PinMode lastMode[GPIO_NUM_MAX] = {(PinMode)0};
static bool lastWrite[GPIO_NUM_MAX];

void GPIO::pinMode(int pin, PinMode mode) {
  if (lastMode[pin] != mode) {
    gpio_reset_pin((gpio_num_t)pin);
    gpio_config_t cfg = {
      .pin_bit_mask = 1ULL << pin,
      .mode = mode == INPUT ? GPIO_MODE_INPUT : GPIO_MODE_OUTPUT, // Also, OD variants
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&cfg);
    lastMode[pin] = mode;
    gpio_set_direction((gpio_num_t)pin, (gpio_mode_t)mode);
  }
}

void GPIO::digitalWrite(int pin, bool value) {
  lastWrite[pin] = value;
  gpio_set_level((gpio_num_t)pin, value);
}

bool GPIO::digitalRead(int pin) {
  if (lastMode[pin] == INPUT) {
    return gpio_get_level((gpio_num_t)pin);
  } else {
    return lastWrite[pin];
  }
}

// The ESP-IDF adc stack is thread safe, but not re-entrant, so we only initialise this once
static adc_oneshot_unit_handle_t adc_handle = NULL;

int GPIO::analogRead(int pin, adc_atten_t atten, bool calibrated) {
  if (!adc_handle) {
    adc_oneshot_unit_init_cfg_t unit_config = { ADC_UNIT_1, ADC_DIGI_CLK_SRC_DEFAULT, ADC_ULP_MODE_DISABLE };
    if (ESP_ERROR_CHECK_WITHOUT_ABORT(adc_oneshot_new_unit(&unit_config, &adc_handle)) != ESP_OK) {
      ESP_LOGE(TAG, "Failed to create ADC unit for pin %d", pin);
      return -1;
    }
  }

  adc_oneshot_chan_cfg_t config = {
    .atten = atten, // = approx 400mv -> 3800mv. Note: battery is divided by 2 in hardware
    .bitwidth = ADC_BITWIDTH_12,
  };
  // ESP_LOGI(TAG, "adc_oneshot_config_channel channel %d, atten %d", pin, atten);
  ESP_ERROR_CHECK(adc_oneshot_config_channel(adc_handle, (adc_channel_t)pin, &config));

  adc_cali_handle_t adc1_cali_chan_handle = NULL;
  if (calibrated) {
    if (!adc_calibration_init(ADC_UNIT_1, (adc_channel_t)pin, ADC_ATTEN_DB_12, &adc1_cali_chan_handle)) {
      ESP_LOGW(TAG,"ADC unit 1 failed calibration init");
      adc1_cali_chan_handle = NULL;
    }
  }

  int adc_reading = 0;
  ESP_ERROR_CHECK(adc_oneshot_read(adc_handle, (adc_channel_t)pin, &adc_reading));

  if (adc1_cali_chan_handle) {
    int voltage;
    adc_cali_raw_to_voltage(adc1_cali_chan_handle, adc_reading, &voltage);
    adc_calibration_deinit(adc1_cali_chan_handle);
    adc_reading = voltage;
  }
  // ESP_ERROR_CHECK(adc_oneshot_del_unit(adc_handle));
  return adc_reading;
}

int GPIO::analogReadMilliVolts(int pin) {
  return analogRead(pin, ADC_ATTEN_DB_12, true);
}

/*---------------------------------------------------------------
        ADC Calibration
---------------------------------------------------------------*/
static bool adc_calibration_init(adc_unit_t unit, adc_channel_t channel, adc_atten_t atten, adc_cali_handle_t *out_handle)
{
    adc_cali_handle_t handle = NULL;
    esp_err_t ret = ESP_FAIL;
    bool calibrated = false;

#if ADC_CALI_SCHEME_CURVE_FITTING_SUPPORTED
    if (!calibrated) {
        adc_cali_curve_fitting_config_t cali_config = {
            .unit_id = unit,
            .chan = channel,
            .atten = atten,
            .bitwidth = ADC_BITWIDTH_DEFAULT,
        };
        ret = adc_cali_create_scheme_curve_fitting(&cali_config, &handle);
        if (ret == ESP_OK) {
            calibrated = true;
        }
    }
#endif

#if ADC_CALI_SCHEME_LINE_FITTING_SUPPORTED
    if (!calibrated) {
        ESP_LOGI(TAG, "calibration scheme version is %s", "Line Fitting");
        adc_cali_line_fitting_config_t cali_config = {
            .unit_id = unit,
            .atten = atten,
            .bitwidth = ADC_BITWIDTH_DEFAULT,
        };
        ret = adc_cali_create_scheme_line_fitting(&cali_config, &handle);
        if (ret == ESP_OK) {
            calibrated = true;
        }
    }
#endif

    *out_handle = handle;
    if (ret == ESP_ERR_NOT_SUPPORTED || !calibrated) {
        ESP_LOGW(TAG, "eFuse not burnt, skip software calibration");
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Invalid arg or no memory (%d)", ret);
    }

    return calibrated;
}

static void adc_calibration_deinit(adc_cali_handle_t handle)
{
#if ADC_CALI_SCHEME_CURVE_FITTING_SUPPORTED
    ESP_ERROR_CHECK(adc_cali_delete_scheme_curve_fitting(handle));

#elif ADC_CALI_SCHEME_LINE_FITTING_SUPPORTED
    ESP_LOGI(TAG, "deregister %s calibration scheme", "Line Fitting");
    ESP_ERROR_CHECK(adc_cali_delete_scheme_line_fitting(handle));
#endif
}