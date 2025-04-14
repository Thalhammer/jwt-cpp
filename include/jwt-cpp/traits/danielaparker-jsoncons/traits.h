#ifndef JWT_CPP_DANIELAPARKER_JSONCONS_TRAITS_H
#define JWT_CPP_DANIELAPARKER_JSONCONS_TRAITS_H

#define JWT_DISABLE_PICOJSON
#define JSONCONS_NO_DEPRECATED

#include "jsoncons/json.hpp"
#include "jwt-cpp/jwt.h"

#include <sstream>

namespace jwt {
	/**
	 * \brief Namespace containing all the json_trait implementations for a jwt::basic_claim.
	*/
	namespace traits {
		/// basic_claim's JSON trait implementation for jsoncons.
		struct danielaparker_jsoncons {
			// Needs at least https://github.com/danielaparker/jsoncons/commit/28c56b90ec7337f98a5b8942574590111a5e5831
			static_assert(jsoncons::version().major > 0);

			using json = jsoncons::json;
			using value_type = json;

			struct object_type {
				using key_type = json::key_type;
				using mapped_type = json;
				using value_type = std::pair<const key_type, mapped_type>;
				using size_type = size_t;
				using iterator = json::object_iterator;
				using const_iterator = json::const_object_iterator;

				object_type() = default;
				object_type(const object_type& o) : json_(o) {}
				explicit object_type(const json& j) : json_(j) {}
				explicit object_type(object_type&& o) noexcept : json_(std::move(o)) {}
				~object_type() = default;

				object_type& operator=(const object_type& o) {
					json_ = o.json_;
					return *this;
				}

				object_type& operator=(object_type&& o) noexcept {
					json_ = std::move(o.json_);
					return *this;
				}

				// Add missing C++11 subscription operator
				mapped_type& operator[](const key_type& key) { return json_[key]; }

				// Add missing C++11 element access
				const mapped_type& at(const key_type& key) const { return json_.at(key); }

				// Add missing C++11 lookup method
				size_type count(const key_type& key) const { return json_.count(key); }

				iterator begin() { return json_.object_range().begin(); }
				iterator end() { return json_.object_range().end(); }
				const_iterator begin() const { return json_.object_range().cbegin(); }
				const_iterator end() const { return json_.object_range().cend(); }
				const_iterator cbegin() const { return json_.object_range().cbegin(); }
				const_iterator cend() const { return json_.object_range().cend(); }

			private:
				json json_;
			};

			struct array_type {
				using value_type = json;
				using size_type = size_t;
				using iterator = json::array_iterator;
				using const_iterator = json::const_array_iterator;

				array_type() = default;
				array_type(const array_type& a) : json_(a) {}
				explicit array_type(const json& j) : json_(j) {}
				explicit array_type(array_type&& a) noexcept : json_(std::move(a)) {}
				template<typename Iterator>
				array_type(Iterator first, Iterator last) {
					json_ = json::array();
					for (auto it = first; it != last; ++it) {
						json_.push_back(*it);
					}
				}
				~array_type() = default;

				array_type& operator=(const array_type& o) {
					json_ = o.json_;
					return *this;
				}

				array_type& operator=(array_type&& o) noexcept {
					json_ = std::move(o.json_);
					return *this;
				}

				value_type& operator[](size_type index) { return json_[index]; }

				const value_type& at(size_type index) const { return json_.at(index); }

				value_type const& front() const { return json_.at(0); }

				void push_back(const value_type& val) { json_.push_back(val); }

				iterator begin() { return json_.array_range().begin(); }
				iterator end() { return json_.array_range().end(); }
				const_iterator begin() const { return json_.array_range().cbegin(); }
				const_iterator end() const { return json_.array_range().cend(); }
				const_iterator cbegin() const { return json_.array_range().cbegin(); }
				const_iterator cend() const { return json_.array_range().cend(); }

			private:
				json json_;
			};

			using string_type = std::string; // current limitation of traits implementation
			using number_type = double;
			using integer_type = int64_t;
			using boolean_type = bool;

			static jwt::json::type get_type(const json& val) {
				using jwt::json::type;

				if (val.type() == jsoncons::json_type::bool_value) return type::boolean;
				if (val.type() == jsoncons::json_type::int64_value) return type::integer;
				if (val.type() == jsoncons::json_type::uint64_value) return type::integer;
				if (val.type() == jsoncons::json_type::half_value) return type::number;
				if (val.type() == jsoncons::json_type::double_value) return type::number;
				if (val.type() == jsoncons::json_type::string_value) return type::string;
				if (val.type() == jsoncons::json_type::array_value) return type::array;
				if (val.type() == jsoncons::json_type::object_value) return type::object;

				throw std::logic_error("invalid type");
			}

			static object_type as_object(const json& val) {
				if (val.type() != jsoncons::json_type::object_value) throw std::bad_cast();
				return object_type(val);
			}

			static array_type as_array(const json& val) {
				if (val.type() != jsoncons::json_type::array_value) throw std::bad_cast();
				return array_type(val);
			}

			static string_type as_string(const json& val) {
				if (val.type() != jsoncons::json_type::string_value) throw std::bad_cast();
				return val.as_string();
			}

			static number_type as_number(const json& val) {
				if (get_type(val) != jwt::json::type::number) throw std::bad_cast();
				return val.as_double();
			}

			static integer_type as_integer(const json& val) {
				if (get_type(val) != jwt::json::type::integer) throw std::bad_cast();
				return val.as<integer_type>();
			}

			static boolean_type as_boolean(const json& val) {
				if (val.type() != jsoncons::json_type::bool_value) throw std::bad_cast();
				return val.as_bool();
			}

			static bool parse(json& val, const std::string& str) {
				val = json::parse(str);
				return true;
			}

			static std::string serialize(const json& val) {
				std::ostringstream os;
				os << jsoncons::print(val);
				return os.str();
			}
		};
	} // namespace traits
} // namespace jwt

namespace jsoncons {
	template<typename Json>
	struct json_type_traits<Json, jwt::traits::danielaparker_jsoncons::object_type> {

		using allocator_type = typename Json::allocator_type;

		static bool is(const Json&) noexcept { return true; }

		static jwt::traits::danielaparker_jsoncons::object_type as(const Json& j) {
			jwt::traits::danielaparker_jsoncons::object_type o;
			for (const auto& item : j.object_range()) {
				o[item.key()] = item.value();
			}
			return o;
		}

		static Json to_json(const jwt::traits::danielaparker_jsoncons::object_type& val) {
			jsoncons::json j = jsoncons::json::object();
			for (const auto& item : val) {
				j[item.key()] = item.value();
			}
			return j;
		}

		static Json to_json(const jwt::traits::danielaparker_jsoncons::object_type& val, const allocator_type&) {
			return to_json(val);
		}
	};

	template<typename Json>
	struct json_type_traits<Json, jwt::traits::danielaparker_jsoncons::array_type> {

		using allocator_type = typename Json::allocator_type;

		static bool is(const Json&) noexcept { return true; }

		static jwt::traits::danielaparker_jsoncons::array_type as(const Json& j) {
			jwt::traits::danielaparker_jsoncons::array_type a;
			for (const auto& item : j.array_range()) {
				a.push_back(item);
			}
			return a;
		}

		static Json to_json(const jwt::traits::danielaparker_jsoncons::array_type& val) {
			jsoncons::json a = jsoncons::json::array();
			for (const auto& item : val) {
				a.push_back(item);
			}
			return a;
		}

		static Json to_json(const jwt::traits::danielaparker_jsoncons::array_type& val, const allocator_type&) {
			return to_json(val);
		}
	};
} // namespace jsoncons

#endif // JWT_CPP_DANIELAPARKER_JSONCONS_TRAITS_H
