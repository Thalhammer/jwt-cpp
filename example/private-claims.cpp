#include <jwt-cpp/jwt.h>
#include <nlohmann/json.hpp>

#include <iostream>
#include <sstream>

using sec = std::chrono::seconds;
using min = std::chrono::minutes;

std::string make_pico_token() {
	jwt::claim from_raw_json;
	std::istringstream iss{R"##({"api":{"array":[1,2,3],"null":null}})##"};
	iss >> from_raw_json;

	jwt::claim::set_t list{"once", "twice"};

	std::vector<int64_t> big_numbers{727663072ULL, 770979831ULL, 427239169ULL, 525936436ULL};

	const auto time = jwt::date::clock::now();

	return jwt::create()
		.set_type("JWT")
		.set_issuer("auth.mydomain.io")
		.set_audience("mydomain.io")
		.set_issued_at(time)
		.set_not_before(time + sec{15})
		.set_expires_at(time + sec{15} + min{2})
		.set_payload_claim("boolean", picojson::value(true))
		.set_payload_claim("integer", picojson::value(int64_t{12345}))
		.set_payload_claim("precision", picojson::value(12.345))
		.set_payload_claim("strings", jwt::claim(list))
		.set_payload_claim("array", jwt::claim(big_numbers.begin(), big_numbers.end()))
		.set_payload_claim("object", from_raw_json)
		.sign(jwt::algorithm::none{});
}

std::string make_nlohmann_token() {
	struct nlohmann_traits {
		using json = nlohmann::json;
		using value_type = json;
		using object_type = json::object_t;
		using array_type = json::array_t;
		using string_type = std::string;
		using number_type = json::number_float_t;
		using integer_type = json::number_integer_t;
		using boolean_type = json::boolean_t;

		static jwt::json::type get_type(const json& val) {
			using jwt::json::type;

			if (val.type() == json::value_t::boolean) return type::boolean;
			if (val.type() == json::value_t::number_integer) return type::integer;
			// nlohmann internally tracks two types of integers
			if (val.type() == json::value_t::number_unsigned) return type::integer;
			if (val.type() == json::value_t::number_float) return type::number;
			if (val.type() == json::value_t::string) return type::string;
			if (val.type() == json::value_t::array) return type::array;
			if (val.type() == json::value_t::object) return type::object;
			throw std::logic_error("invalid type");
		}

		static json::object_t as_object(const json& val) {
			if (val.type() != json::value_t::object) throw std::bad_cast();
			return val.get<json::object_t>();
		}

		static std::string as_string(const json& val) {
			if (val.type() != json::value_t::string) throw std::bad_cast();
			return val.get<std::string>();
		}

		static json::array_t as_array(const json& val) {
			if (val.type() != json::value_t::array) throw std::bad_cast();
			return val.get<json::array_t>();
		}

		static int64_t as_int(const json& val) {
			switch (val.type()) {
			case json::value_t::number_integer:
			case json::value_t::number_unsigned: return val.get<int64_t>();
			default: throw std::bad_cast();
			}
		}

		static bool as_bool(const json& val) {
			if (val.type() != json::value_t::boolean) throw std::bad_cast();
			return val.get<bool>();
		}

		static double as_number(const json& val) {
			if (val.type() != json::value_t::number_float) throw std::bad_cast();
			return val.get<double>();
		}

		static bool parse(json& val, std::string str) {
			val = json::parse(str.begin(), str.end());
			return true;
		}

		static std::string serialize(const json& val) { return val.dump(); }
	};

	using claim = jwt::basic_claim<nlohmann_traits>;

	claim from_raw_json;
	std::istringstream iss{R"##({"api":{"array":[1,2,3],"null":null}})##"};
	iss >> from_raw_json;

	claim::set_t list{"once", "twice"};

	std::vector<int64_t> big_numbers{727663072ULL, 770979831ULL, 427239169ULL, 525936436ULL};

	const auto time = jwt::date::clock::now();

	return jwt::create<nlohmann_traits>()
		.set_type("JWT")
		.set_issuer("auth.mydomain.io")
		.set_audience("mydomain.io")
		.set_issued_at(time)
		.set_not_before(time + sec{15})
		.set_expires_at(time + sec{15} + min{2})
		.set_payload_claim("boolean", true)
		.set_payload_claim("integer", 12345)
		.set_payload_claim("precision", 12.345)
		.set_payload_claim("strings", list)
		.set_payload_claim("array", {big_numbers.begin(), big_numbers.end()})
		.set_payload_claim("object", from_raw_json)
		.sign(jwt::algorithm::none{});
}

int main() {
	const auto token = make_pico_token();
	auto decoded = jwt::decode(token);

	for (auto& e : decoded.get_payload_claims())
		std::cout << e.first << " = " << e.second << std::endl;

	const auto api_array = decoded.get_payload_claims()["object"].to_json().get("api").get("array");
	std::cout << "api array = " << api_array << std::endl;
}
