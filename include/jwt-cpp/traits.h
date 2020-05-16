#pragma once

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

        template<typename value, 
            typename object, 
            typename array, 
            typename string, 
            typename number, 
            typename integer,
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
            using integer = integer;
            // using null = null;
        };
    }
}

struct picojson_traits : traits<
    picojson::value, 
    picojson::object, 
    picojson::array, 
    std::string, 
    double,
    int64_t, 
    bool> {
    static jwt::json::type get_type(const traits::value& val) {
        using jwt::json::type;

        if (val.is<picojson::null>()) return type::null;
	else if (val.is<bool>()) return type::boolean;
	else if (val.is<int64_t>()) return type::integer;
	else if (val.is<double>()) return type::number;
	else if (val.is<std::string>()) return type::string;
	else if (val.is<picojson::array>()) return type::array;
	else if (val.is<picojson::object>()) return type::object;
	else throw std::logic_error("invalid type");
		
    }
};
    
