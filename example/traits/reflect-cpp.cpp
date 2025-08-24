#include "jwt-cpp/jwt.h"
#include "jwt-cpp/traits/reflect-cpp/traits.h" // the trait adapter

#include <chrono>
#include <iostream>
#include <string>

int main() {
	using R = jwt::traits::reflect_cpp;

	try {
		// Build a small JSON object claim using the trait's value_type
		R::object_type ns_obj;
		ns_obj["api-x"] = R::value_type(1); // {"api-x": 1}

		// Build an array claim: [100, 20, 10]
		R::array_type arr;
		arr.emplace_back(100);
		arr.emplace_back(20);
		arr.emplace_back(10);

		// Wrap the native JSON values into jwt::basic_claim<R>
		jwt::basic_claim<R> ns_claim(R::value_type(ns_obj));
		jwt::basic_claim<R> arr_claim(R::value_type(arr));

		// Create a token using the reflect-cpp trait (HS256)
		const std::string secret = "secret";
		const auto now = std::chrono::system_clock::now();

		const auto token = jwt::create<R>()
							   .set_type("JWT")
							   .set_algorithm("HS256")
							   .set_issuer("auth0")
							   .set_subject("demo")
							   .set_audience("example")
							   .set_issued_at(now)
							   .set_not_before(now - std::chrono::seconds{5})
							   .set_expires_at(now + std::chrono::minutes{10})
							   .set_payload_claim("namespace", ns_claim)
							   .set_payload_claim("numbers", arr_claim)
							   .sign(jwt::algorithm::hs256{secret});

		std::cout << "token: " << token << "\n";

		// Decode with the same trait
		const auto decoded = jwt::decode<R>(token);

		// Access header/payload fields
		std::cout << "alg: " << decoded.get_algorithm() << "\n";
		std::cout << "typ: " << decoded.get_type() << "\n";
		if (decoded.has_issuer()) std::cout << "iss: " << decoded.get_issuer() << "\n";

		// Verify with the same trait
		const auto verifier = jwt::verify<R>().allow_algorithm(jwt::algorithm::hs256{secret}).with_issuer("auth0");

		verifier.verify(decoded);
		std::cout << "verification: OK\n";

		// Read back our custom claims using the trait accessors
		if (decoded.has_payload_claim("namespace")) {
			const auto c = decoded.get_payload_claim("namespace");
			if (c.get_type() == jwt::json::type::object) {
				const auto& obj = c.as_object(); // R::object_type (map-like)
				const auto it = obj.find("api-x");
				if (it != obj.end()) {
					// it->second is R::value_type
					// print integer if present
					// (rfl::Generic can be visited, but jwt-cpp trait exposes typed helpers)
					// Keep it simple and rely on serialization through the trait:
					std::cout << "namespace.api-x present\n";
				}
			}
		}

		if (decoded.has_payload_claim("numbers")) {
			const auto c = decoded.get_payload_claim("numbers");
			if (c.get_type() == jwt::json::type::array) {
				const auto& a = c.as_array(); // R::array_type (vector-like)
				std::cout << "numbers.size: " << a.size() << "\n";
			}
		}

	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}

	return 0;
}
