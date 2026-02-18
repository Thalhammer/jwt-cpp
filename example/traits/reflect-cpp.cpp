#include "jwt-cpp/jwt.h"
#include "jwt-cpp/traits/reflect-cpp/traits.h"

#include <chrono>
#include <iostream>

int main() {
	using sec = std::chrono::seconds;
	using min = std::chrono::minutes;
	using traits = jwt::traits::reflect_cpp;
	using claim = jwt::basic_claim<traits>;

	// Load a raw JSON object into a claim (reflect-cpp: parse -> wrap)
	claim from_raw_json;
	{
		traits::value_type value;
		// Mirrors the nlohmann example’s JSON
		const auto* const json_text = R"##({"api":{"array":[1,2,3],"null":null}})##";
		if (!traits::parse(value, json_text)) {
			std::cerr << "failed to parse raw json\n";
			return 1;
		}
		from_raw_json = claim{std::move(value)};
	}

	claim::set_t list{"once", "twice"};
	std::vector<int64_t> big_numbers{727663072LL, 770979831LL, 427239169LL, 525936436LL};

	// Build an array claim from the big_numbers vector
	traits::array_type arr;
	arr.reserve(big_numbers.size());
	for (auto val : big_numbers) {
		arr.emplace_back(val);
	}
	claim array_claim{traits::value_type{arr}};
	claim strings_claim{list.begin(), list.end()};

	const auto time = jwt::date::clock::now();
	const auto token = jwt::create<traits>()
						   .set_type("JWT")
						   .set_issuer("auth.mydomain.io")
						   .set_audience("mydomain.io")
						   .set_issued_at(time)
						   .set_not_before(time)
						   .set_expires_at(time + min{2} + sec{15})
						   .set_payload_claim("boolean", true)
						   .set_payload_claim("integer", 12345)
						   .set_payload_claim("precision", 12.3456789)
						   .set_payload_claim("strings", strings_claim) // <— fixed
						   .set_payload_claim("array", array_claim)
						   .set_payload_claim("object", from_raw_json)
						   .sign(jwt::algorithm::none{});

	const auto decoded = jwt::decode<traits>(token);

	// Access payload /object/api/array using reflect-cpp's Result-returning get()
	{
		const auto obj_v = decoded.get_payload_claim("object").to_json(); // R::value_type
		const auto obj = traits::as_object(obj_v);						  // rfl::Object<rfl::Generic>

		if (auto api_res = obj.get("api"); api_res) {				 // rfl::Result<rfl::Generic>
			const auto api_obj = traits::as_object(api_res.value()); // nested object

			if (auto arr_res = api_obj.get("array"); arr_res) {
				const auto& nested = traits::as_array(arr_res.value()); // vector-like
				std::cout << "payload /object/api/array = " << rfl::json::write(nested) << '\n';
			} else {
				std::cout << "payload /object/api/array missing\n";
			}
		} else {
			std::cout << "payload /object/api missing\n";
		}
	}

	jwt::verify<traits>()
		.allow_algorithm(jwt::algorithm::none{})
		.with_issuer("auth.mydomain.io")
		.with_audience("mydomain.io")
		.with_claim("object", from_raw_json)
		.verify(decoded);

	return 0;
}
