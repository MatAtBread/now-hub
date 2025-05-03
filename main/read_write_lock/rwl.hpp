#ifndef RWL_H
#define RWL_H
#include <esp_log.h>

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
  friend class Locked<T>;
  friend class WriteLocked<T>;

 public:
  SerializedStatic(T& obj) : obj(obj) {
    xRecursiveMutex = xSemaphoreCreateRecursiveMutex();
  }
  ~SerializedStatic() {
    vSemaphoreDelete(xRecursiveMutex);
  }
};

template <typename T>
class Locked {
 protected:
  SerializedStatic<T>* l;

 public:
  Locked(SerializedStatic<T>* l) : l(l) {
    xSemaphoreTakeRecursive(l->xRecursiveMutex, portMAX_DELAY);
  }
  ~Locked() {
    xSemaphoreGiveRecursive(l->xRecursiveMutex);
  }
  operator T&() { return l->obj; }
};
#endif