#include <iostream>
#include <jwt-cpp/jwt.h>

int main(int argc, const char** argv) {
	std::string token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
	auto decoded = jwt::decode(token);

	for (auto& e : decoded.get_payload_claims())
		std::cout << e.first << " = " << e.second << std::endl;
}
