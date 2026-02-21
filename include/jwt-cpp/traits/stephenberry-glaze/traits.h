#ifndef JWT_CPP_STEPHENBERRY_GLAZE_TRAITS_H
#define JWT_CPP_STEPHENBERRY_GLAZE_TRAITS_H

#include "jwt-cpp/jwt.h"
#include <glaze/glaze.hpp>

namespace jwt {
	/**
	 * \brief Namespace containing all the json_trait implementations for a jwt::basic_claim.
	*/
	namespace traits {
		struct stephenberry_glaze {
			using json = glz::json_t;
			using value_type = json;			// ← ключевое
			using object_type = json::object_t; // map<string, json_t>
			using array_type = json::array_t;	// vector<json_t>
			using string_type = std::string;
			using number_type = double;
			using integer_type = std::int64_t;
			using boolean_type = bool;

			static jwt::json::type get_type(const value_type& val) {
				using jwt::json::type;

				if (val.is_object()) return type::object;
				if (val.is_array()) return type::array;
				if (val.is_string()) return type::string;
				if (val.is_boolean()) return type::boolean;

				// Если у json_t нет отдельного integer-типа:
				if (val.is_number()) return type::number;

				if (val.is_null()) throw std::logic_error("invalid type: null");
				throw std::logic_error("invalid type");
			}

			static object_type as_object(const value_type& val) {
				if (!val.is_object()) throw std::bad_cast();
				return std::get<object_type>(val.data);
			}

			static array_type as_array(const value_type& val) {
				if (!val.is_array()) throw std::bad_cast();
				return std::get<array_type>(val.data);
			}

			static string_type as_string(const value_type& val) {
				if (!val.is_string()) throw std::bad_cast();
				return std::get<std::string>(val.data);
			}

			static number_type as_number(const value_type& val) {
				if (!val.is_number()) throw std::bad_cast();
				return std::get<double>(val.data);
			}

			static integer_type as_integer(const value_type& val) {
				if (!val.is_number()) throw std::bad_cast();
				double d = std::get<double>(val.data);
				// optional: ensure it's an exact int64
				auto i = static_cast<integer_type>(d);
				if (static_cast<double>(i) != d) throw std::bad_cast();
				return i;
			}

			static boolean_type as_boolean(const value_type& val) {
				if (!val.is_boolean()) throw std::bad_cast();
				return std::get<bool>(val.data);
			}

			static bool parse(value_type& val, string_type str) {
				if (auto r = glz::read_json(val, str); r) { return false; }
				return true;
			}

			static string_type serialize(const value_type& val) {
				if (auto r = glz::write_json(val); r) return *r;
				throw std::runtime_error("serialize failed");
			}
		};
	} // namespace traits
} // namespace jwt

#endif // JWT_CPP_STEPHENBERRY_GLAZE_TRAITS_H