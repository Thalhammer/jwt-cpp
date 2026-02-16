#ifndef JWT_CPP_GLAZE_TRAITS_H
#define JWT_CPP_GLAZE_TRAITS_H

#define JWT_DISABLE_PICOJSON
#include "jwt-cpp/jwt.h"

#include <cmath>
#include <glaze/glaze.hpp>

namespace jwt {
	/**
	 * \brief Namespace containing all the json_trait implementations for a jwt::basic_claim.
	*/
	namespace traits {
		/// basic_claim's JSON trait implementation for Glaze
		struct glaze {
			using value_type = glz::generic;
			using object_type = value_type::object_t;
			using array_type = value_type::array_t;
			using string_type = std::string;
			using number_type = double;
			using integer_type = std::int64_t;
			using boolean_type = bool;

			static bool is_integer(double value) { return std::trunc(value) == value; }

			static jwt::json::type get_type(const value_type& val) {
				using jwt::json::type;

				if (val.is_object()) { return type::object; }
				if (val.is_array()) { return type::array; }
				if (val.is_string()) { return type::string; }
				if (val.is_number() && is_integer(val.get_number())) { return type::integer; }
				if (val.is_number()) { return type::number; }
				if (val.is_boolean()) { return type::boolean; }

				throw std::logic_error("invalid type");
			}

			static object_type as_object(const value_type& val) {
				if (get_type(val) != jwt::json::type::object) throw std::bad_cast();
				return val.get_object();
			}

			static array_type as_array(const value_type& val) {
				if (get_type(val) != jwt::json::type::array) throw std::bad_cast();
				return val.get_array();
			}

			static string_type as_string(const value_type& val) {
				if (get_type(val) != jwt::json::type::string) throw std::bad_cast();
				return val.get_string();
			}

			static integer_type as_integer(const value_type& val) {
				if (get_type(val) != jwt::json::type::integer) throw std::bad_cast();
				 return val.get_number();
			}

			static boolean_type as_boolean(const value_type& val) {
				if (get_type(val) != jwt::json::type::boolean) throw std::bad_cast();
				return val.get_boolean();
			}

			static number_type as_number(const value_type& val) {
				if (get_type(val) != jwt::json::type::number) throw std::bad_cast();
				return val.get_number();
			}

			static bool parse(value_type& val, string_type str) {
				if (auto parsed = glz::read_json<glz::generic>(str); parsed) {
					val = parsed.value();
					return true;
				}

				return false;
			}

			static string_type serialize(const value_type& val) { return val.dump().value(); }
		};
	} // namespace traits
} // namespace jwt

#endif // JWT_CPP_BOOSTJSON_TRAITS_H
