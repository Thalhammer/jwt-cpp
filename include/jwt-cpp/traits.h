#pragma once
#include <type_traits>

namespace jwt {
    namespace json {
        enum class type {
            null, 
            boolean, 
            integer,
            number, 
            string, 
            array, 
            object, 
        };

        template<typename value_t,
            typename object_t,
            typename array_t,
            typename string_t,
            typename number_t,
            typename integer_t,
            typename boolean_t,
            typename null_t = void>
        struct traits {
            using value = value_t;
            using object = object_t;
            using array = array_t;
            using string = string_t;
            using number = number_t;
            using boolean = boolean_t;
            using integer = integer_t;
            using null = null_t;

            static_assert(std::is_constructible<value, object>::value, "needts a ctor which takes object type");
            static_assert(std::is_constructible<value, string>::value, "needts a ctor which takes string type");
        };
    }
}
