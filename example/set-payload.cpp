/// @file set-payload.cpp
#include <iostream>
#include <jwt-cpp/jwt.h>

int main() {
	std::string json = R"(
		{
			"exp": 1711706773,
			"iat": 1710706773,
			"set": {
				"complex": "json",
				"payload": "using",
				"only": {
					"one": "line"
				}
			}
		}
	)";

	auto token = jwt::create()
		.set_type("JWT")
		.set_payload(json)
		.set_payload_claim("sample", jwt::claim(std::string{"test"}))
		.sign(jwt::algorithm::hs256("test"));
	
	std::cout << "token:\n" << token << std::endl;
}
