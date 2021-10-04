#include <iostream>
#include "jwt-cpp/traits/danielaparker-jsoncons/defaults.h"

int main() {
	std::string token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
	auto decoded = jwt::decode(token);

	for (auto& e : decoded.payload_claims)
		std::cout << e.key() << " = " << e.value() << std::endl;
}
