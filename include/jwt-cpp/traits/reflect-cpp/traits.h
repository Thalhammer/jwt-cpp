#pragma once

#ifndef JWT_DISABLE_PICOJSON
#define JWT_DISABLE_PICOJSON
#endif

#include "jwt-cpp/jwt.h"

#include <rfl/Generic.hpp>
#include <rfl/json.hpp>
#include <stdexcept>
#include <variant>

namespace jwt::traits {

	struct reflect_cpp {

		using value_type = rfl::Generic;
		using object_type = rfl::Generic::Object;
		using array_type = rfl::Generic::Array;
		using string_type = std::string;
		using number_type = double;
		using integer_type = int64_t;
		using boolean_type = bool;

		template<class... Ts>
		struct variant_overloaded : Ts... {
			using Ts::operator()...;
		};

		static jwt::json::type get_type(const value_type& val) {
			return std::visit(
				variant_overloaded{
					[](boolean_type const&) -> jwt::json::type { return jwt::json::type::boolean; },
					[](integer_type const&) -> jwt::json::type { return jwt::json::type::integer; },
					[](number_type const&) -> jwt::json::type { return jwt::json::type::number; },
					[](string_type const&) -> jwt::json::type { return jwt::json::type::string; },
					[](array_type const&) -> jwt::json::type { return jwt::json::type::array; },
					[](object_type const&) -> jwt::json::type { return jwt::json::type::object; },
					[](std::nullopt_t const&) -> jwt::json::type { throw std::logic_error("invalid type"); },
				},
				val.get());
		}

		static object_type as_object(const value_type& val) {
			const auto& variant = val.get();
			if (!std::holds_alternative<object_type>(variant)) throw std::bad_cast();
			return std::get<object_type>(variant);
		}

		static array_type as_array(const value_type& val) {
			const auto& variant = val.get();
			if (!std::holds_alternative<array_type>(variant)) throw std::bad_cast();
			return std::get<array_type>(variant);
		}

		static string_type as_string(const value_type& val) {
			const auto& variant = val.get();
			if (!std::holds_alternative<string_type>(variant)) throw std::bad_cast();
			return std::get<string_type>(variant);
		}

		static integer_type as_integer(const value_type& val) {
			const auto& variant = val.get();
			if (!std::holds_alternative<integer_type>(variant)) throw std::bad_cast();
			return std::get<integer_type>(variant);
		}

		static boolean_type as_boolean(const value_type& val) {
			const auto& variant = val.get();
			if (!std::holds_alternative<boolean_type>(variant)) throw std::bad_cast();
			return std::get<boolean_type>(variant);
		}

		static number_type as_number(const value_type& val) {
			const auto& variant = val.get();
			if (!std::holds_alternative<number_type>(variant)) throw std::bad_cast();
			return std::get<number_type>(variant);
		}

		static bool parse(value_type& out, string_type const& json) {
			auto res = rfl::json::read<rfl::Generic>(json);
			if (res) {
				out = *std::move(res);
				return true;
			}
			return false;
		}

		static std::string serialize(const value_type& val) { return rfl::json::write(val); }
	};

} // namespace jwt::traits
