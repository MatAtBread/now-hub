#include <type_traits>

void* _bind(void *self, void *f);

template<typename ReturnType, typename Self, typename... Args>
ReturnType (*bind(Self *self, ReturnType (Self::*func)(Args...)))(Args...) {
    return reinterpret_cast<ReturnType (*)(Args...)>(
        _bind(self, reinterpret_cast<void*>(func))
    );
}


// template<typename ReturnType, typename Self, typename... Args>
// std::enable_if_t<std::is_member_function_pointer_v<ReturnType (Self::*)(Args...)>, ReturnType (*)(Args...)>
// bind(Self *self, ReturnType (Self::*func)(Args...)) {
//     return reinterpret_cast<ReturnType (*)(Args...)>(
//         _bind(self, reinterpret_cast<void*>(func))
//     );
// }

template<typename ReturnType, typename Base, typename Derived, typename... Args>
std::enable_if_t<std::is_base_of_v<Base, Derived> && std::is_member_function_pointer_v<ReturnType (Base::*)(Args...)>, ReturnType (*)(Args...)>
bind(Derived *self, ReturnType (Base::*func)(Args...)) {
    return reinterpret_cast<ReturnType (*)(Args...)>(
        _bind(self, reinterpret_cast<void*>(func))
    );
}

template<typename T>
void unbind(T f);

//#define bind(THIS, MFP) _bind(reinterpret_cast<void*>(THIS),reinterpret_cast<void*>(MFP))
