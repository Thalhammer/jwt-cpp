# jwt-cpp
A header only library for creating and validating json web tokens in c++.

## Signature algorithms
jwt-cpp currently supports all algorithms used in normal applications. It does not yet support the optional PS256, PS384, PS512 defined in later versions of the specification. Those are not used in the wild yet and the modular design of jwt-cpp allows one to add them without any problems. If you need them feel free to open a pull request.

## Examples
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

## Contributing
If you have an improvement or found a bug feel free to [open an issue](https://github.com/Thalhammer/jwt-cpp/issues/new) or add the change and create a pull request. If you file a bug please make sure to include as much information about your environment (compiler version, etc.) as possible to help reproduce the issue. If you add a new feature please make sure to also include test cases for it.

## Dependencies
In order to use jwt-cpp you need the following tools.
* libcrypto (openssl or compatible)
* a compiler supporting at least c++11
* basic stl support

In order to build the test cases you also need
* gtest installed in linker path
* pthread