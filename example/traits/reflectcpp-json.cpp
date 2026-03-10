#include "jwt-cpp/jwt.h"
#include "jwt-cpp/traits/reflectcpp-json/traits.h"

#include <chrono>
#include <iostream>

int main() {
	using sec = std::chrono::seconds;
	using min = std::chrono::minutes;
	using traits = jwt::traits::reflectcpp_json;
	using claim = jwt::basic_claim<traits>;

	traits::value_type raw_value;
	traits::parse(raw_value, R"##({"api":{"array":[1,2,3],"null":null}})##");
	claim from_raw_json(raw_value);

	claim::set_t list{"once", "twice"};
	std::vector<int64_t> big_numbers{727663072LL, 770979831LL, 427239169LL, 525936436LL};

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
						   .set_payload_claim("strings", claim(list))
						   .set_payload_claim("array", claim{big_numbers.begin(), big_numbers.end()})
						   .set_payload_claim("object", from_raw_json)
						   .sign(jwt::algorithm::none{});

	const auto decoded = jwt::decode<traits>(token);

	const auto array = decoded.get_payload_claim("object")
						   .to_json()
						   .to_object()
						   .value()["api"]
						   .to_object()
						   .value()["array"]
						   .to_array()
						   .value();
	std::cout << "payload /object/api/array = " << rfl::json::write(array) << '\n';

	jwt::verify<traits>()
		.allow_algorithm(jwt::algorithm::none{})
		.with_issuer("auth.mydomain.io")
		.with_audience("mydomain.io")
		.with_claim("object", from_raw_json)
		.verify(decoded);

	return 0;
}
