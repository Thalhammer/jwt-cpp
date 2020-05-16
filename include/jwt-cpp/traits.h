#pragma once

namespace jwt {
    namespace json {
        template<typename value, 
            enum type, 
            typename object, 
            typename array, 
            typename string, 
            typename number, 
            typename boolean, 
            /*typename null = nullptr*/>
        struct traits {
            using value = value;
            using type = type;
            using object = object;
            using array = array;
            using string = string;
            using number = number;
            using boolean = boolean;
            // using null = null;
        };
    }
}

struct picojson_traits : traits<
    picojson::value, 
    picojson::type, // TBA
    picojson::object, 
    picojson::array, 
    std::string, 
    int64_t, 
    bool> {
};
    
