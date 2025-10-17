/** Wrappers to the underlying ESP-IDF peripheral libraries */
#ifndef IO_H
#define IO_H

#include "hal/gpio_types.h"
#include "hal/adc_types.h"

enum PinMode {
    INPUT = GPIO_MODE_INPUT,
    OUTPUT = GPIO_MODE_OUTPUT
};

class GPIO {
    public:
        static void pinMode(int pin, PinMode mode);
        static void digitalWrite(int pin, bool value);
        static bool digitalRead(int pin);
        static int analogRead(int pin, adc_atten_t atten = ADC_ATTEN_DB_12, bool calibrated = false);
        static int analogReadMilliVolts(int pin);
};

#endif // IO_H