# jwt-cpp
A header only library for creating and validating json web tokens in c++.

Simple example of decoding a token and printing all claims:
```c++
#include <jwt-cpp/jwt.h>
#include <iostream>

int main(int argc, const char** argv) {
	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
	auto decoded = jwt::decode(token);

	for(auto& e : decoded.get_payload_claims())
		std::cout << e.first << " = " << e.second.to_json() << std::endl;
}
```

In order to verify a token you first build a verifier and use it to verify a decoded token.
```c++
auto verifier = jwt::verify()
	.allow_algorithm(jwt::algorithm::hs256{ "secret" })
	.with_issuer("auth0");

verifier.verify(decoded_token);
```
The created verifier is stateless so you can reuse it for different tokens.

Creating a token (and signing) is equally easy.
```c++
auto token = jwt::create()
	.set_issuer("auth0")
	.set_type("JWS")
	.set_payload_claim("sample", std::string("test"))
	.sign(jwt::algorithm::hs256{"secret"});
```
