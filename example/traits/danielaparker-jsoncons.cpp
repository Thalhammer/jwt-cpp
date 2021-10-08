#include "jwt-cpp/traits/danielaparker-jsoncons/traits.h"

#include <iostream>
#include <sstream>

int main() {
	using sec = std::chrono::seconds;
	using min = std::chrono::minutes;
	using claim = jwt::basic_claim<jwt::traits::danielaparker_jsoncons>;
	const create = []() { return jwt::create<jwt::traits::danielaparker_jsoncons>(); };
	const decode = [](const jwt::traits::danielaparker_jsoncons::string_type& token) {
		return jwt::decode<jwt::traits::danielaparker_jsoncons>(token);
	};

	claim from_raw_json;
	std::istringstream iss{R"##({"api":{"array":[1,2,3],"null":null}})##"};
	iss >> from_raw_json;

	claim::set_t list{"once", "twice"};
	std::vector<int64_t> big_numbers{727663072ULL, 770979831ULL, 427239169ULL, 525936436ULL};

	const auto time = jwt::date::clock::now();
	const auto token = create()
						   .set_type("JWT")
						   .set_issuer("auth.mydomain.io")
						   .set_audience("mydomain.io")
						   .set_issued_at(time)
						   .set_not_before(time)
						   .set_expires_at(time + min{2} + sec{15})
						   .set_payload_claim("boolean", true)
						   .set_payload_claim("integer", 12345)
						   .set_payload_claim("precision", 12.3456789)
						   .set_payload_claim("strings", list)
						   .set_payload_claim("array", {big_numbers.begin(), big_numbers.end()})
						   .set_payload_claim("object", from_raw_json)
						   .sign(jwt::algorithm::none{});
	const auto decoded = decode(token);

	const auto api_array = decoded.get_payload_claims()["object"].to_json().get("api").get("array");
	std::cout << "api array = " << api_array << std::endl;
}
