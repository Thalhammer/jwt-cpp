#include "jwt-cpp/traits/stephenberry-glaze/traits.h"
#include <chrono>
#include <iostream>
#include <sstream>
#include <vector>

int main() {
	using sec = std::chrono::seconds;
	using min = std::chrono::minutes;

	using traits = jwt::traits::stephenberry_glaze;
	using claim = jwt::basic_claim<traits>;

	// Parse raw JSON into claim
	claim from_raw_json;
	std::istringstream iss{R"##({"api":{"array":[1,2,3],"null":null}})##"};
	from_raw_json = jwt::basic_claim<jwt::traits::stephenberry_glaze>(
		*glz::read_json<jwt::traits::stephenberry_glaze::value_type>(iss.str()));
	//	iss >> from_raw_json; // no >> for glaze

	// Example claim sets
	claim::set_t list{"once", "twice"};
	std::vector<int64_t> big_numbers{727663072LL, 770979831LL, 427239169LL, 525936436LL};

	// JWT creation
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

	// Decode
	const auto decoded = jwt::decode<traits>(token);

	// Access array inside the payload object
	const auto array =
		traits::as_array(decoded.get_payload_claim("object").to_json().get_object()["api"].get_object()["array"]);
	//	std::cout << "payload /object/api/array = " << array << '\n';
	std::cout << "payload /object/api/array = [ ";
	for (size_t i = 0; i < array.size(); ++i) {
		std::cout << array[i].dump().value_or("error");
		if (i + 1 < array.size()) std::cout << ", ";
	}
	std::cout << " ]\n";

	// Verification
	jwt::verify<traits>()
		.allow_algorithm(jwt::algorithm::none{})
		.with_issuer("auth.mydomain.io")
		.with_audience("mydomain.io")
		.with_claim("object", from_raw_json)
		.verify(decoded);

	return 0;
}
