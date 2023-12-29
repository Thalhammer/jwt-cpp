<img src="https://raw.githubusercontent.com/Thalhammer/jwt-cpp/master/.github/logo.svg" alt="logo" width="100%">

[![License Badge](https://img.shields.io/github/license/Thalhammer/jwt-cpp)](https://github.com/Thalhammer/jwt-cpp/blob/master/LICENSE)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/5f7055e294744901991fd0a1620b231d)](https://app.codacy.com/gh/Thalhammer/jwt-cpp/dashboard)
[![Linux Badge][Linux]][Cross-Platform]
[![MacOS Badge][MacOS]][Cross-Platform]
[![Windows Badge][Windows]][Cross-Platform]
[![Coverage Status](https://coveralls.io/repos/github/Thalhammer/jwt-cpp/badge.svg?branch=master)](https://coveralls.io/github/Thalhammer/jwt-cpp?branch=master)

[![Documentation Badge](https://img.shields.io/badge/Documentation-master-blue)](https://thalhammer.github.io/jwt-cpp/)

[![Stars Badge](https://img.shields.io/github/stars/Thalhammer/jwt-cpp)](https://github.com/Thalhammer/jwt-cpp/stargazers)
[![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/Thalhammer/jwt-cpp?include_prereleases)](https://github.com/Thalhammer/jwt-cpp/releases)
[![ConanCenter package](https://repology.org/badge/version-for-repo/conancenter/jwt-cpp.svg)](https://repology.org/project/jwt-cpp/versions)
[![Vcpkg package](https://repology.org/badge/version-for-repo/vcpkg/jwt-cpp.svg)](https://repology.org/project/jwt-cpp/versions)

[Linux]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/cross-platform/ubuntu-latest/shields.json
[MacOS]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/cross-platform/macos-latest/shields.json
[Windows]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/cross-platform/windows-latest/shields.json
[Cross-Platform]: https://github.com/Thalhammer/jwt-cpp/actions?query=workflow%3A%22Cross-Platform+CI%22

## Overview

A header only library for creating and validating [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) in C++11. For a great introduction, [read this](https://jwt.io/introduction/).

The objective is to deliver a versatile and universally applicable collection of algorithms, classes, and data structures, fostering adaptability and seamless integration with other libraries that you may already be employing.

## Signature algorithms

jwt-cpp supports all the algorithms defined by the specifications. The modular design allows to easily [add additional algorithms](docs/signing.md#custom-signature-algorithms) without any problems. If you need any feel free to create a pull request or [open an issue](https://github.com/Thalhammer/jwt-cpp/issues/new).

For completeness, here is a list of all supported algorithms:

| HMSC  | RSA   | ECDSA  | PSS   | EdDSA   |
| ----- | ----- | ------ | ----- | ------- |
| HS256 | RS256 | ES256  | PS256 | Ed25519 |
| HS384 | RS384 | ES384  | PS384 | Ed448   |
| HS512 | RS512 | ES512  | PS512 |         |
|       |       | ES256K |       |         |

## Getting Started

Installation instructions can be found [here](docs/install.md).

A simple example of decoding a token and printing all [claims](https://tools.ietf.org/html/rfc7519#section-4) ([try it out](https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCIsInNhbXBsZSI6InRlc3QifQ.lQm3N2bVlqt2-1L-FsOjtR6uE-L4E9zJutMWKIe1v1M)):

```cpp
#include <jwt-cpp/jwt.h>
#include <iostream>

int main() {
    std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCIsInNhbXBsZSI6InRlc3QifQ.lQm3N2bVlqt2-1L-FsOjtR6uE-L4E9zJutMWKIe1v1M";
    auto decoded = jwt::decode(token);

    for(auto& e : decoded.get_payload_json())
        std::cout << e.first << " = " << e.second << std::endl;
}
```

You can build and run [this example](example/print-claims.cpp) locally after cloning the repository.

```sh
cmake .
cmake --build . --target print-claims
./print-claims
# iss = "auth0"
# sample = "test"
```

You'll very quickly notice JWT are not encrypted but rather cryptographically signed to
provide [non-repudiation](https://csrc.nist.gov/glossary/term/non_repudiation).

In order to verify a token you first build a verifier and use it to verify a decoded token.

```cpp
auto verifier = jwt::verify()
    .with_issuer("auth0")
    .allow_algorithm(jwt::algorithm::hs256{ "secret" })
    .with_claim("sample", jwt::claim(std::string("test")));

verifier.verify(decoded_token);
```

The verifier is stateless so you can reuse it for different tokens.

Creating the token above (and signing it) is equally as easy.

```cpp
auto token = jwt::create()
    .set_type("JWS")
    .set_issuer("auth0")
    .set_payload_claim("sample", jwt::claim(std::string("test")))
    .sign(jwt::algorithm::hs256{"secret"});
```

If you are looking to issue more unique tokens, checkout out the [examples](https://github.com/Thalhammer/jwt-cpp/tree/master/example) working with RSA public and private keys, elliptic curve tokens, and much more!

### Configuration Options

Building on the goal of providing flexibility.

#### SSL Compatibility

jwt-cpp supports [OpenSSL](https://github.com/openssl/openssl), [LibreSSL](https://github.com/libressl-portable/portable), and [wolfSSL](https://github.com/wolfSSL/wolfssl). For a listed of tested versions, check [this page](docs/ssl.md) for more details.

#### JSON Implementation

There is no hard dependency on a JSON library. Instead, there's a generic `jwt::basic_claim` which is templated around type traits, which described the semantic [JSON types](https://json-schema.org/understanding-json-schema/reference/type.html) for a value, object, array, string, number, integer and boolean, as well as methods to translate between them.

This allows for complete freedom when picking which libraries you want to use. To use one of the provided JSON trait's, see [docs/traits.md](docs/traits.md#selecting-a-json-library) for more information.

##### Providing your own JSON Traits

```cpp
jwt::basic_claim<my_favorite_json_library_traits> claim(json::object({{"json", true},{"example", 0}}));
```

To learn how to writes a trait's implementation, checkout the [these instructions](docs/traits.md#providing-your-own-json-traits)

#### Base64 Options

As for the base64 requirements of JWTs, this library provides `base.h` with all the required implementation; However base64 implementations are very common, with varying degrees of performance. When providing your own base64 implementation, you can define `JWT_DISABLE_BASE64` to remove the jwt-cpp implementation.

## Contributing

If you have an improvement or found a bug feel free to [open an issue](https://github.com/Thalhammer/jwt-cpp/issues/new) or add the change and create a pull request. If you file a bug please make sure to include as much information about your environment (compiler version, etc.) as possible to help reproduce the issue. If you add a new feature please make sure to also include test cases for it.

### Dependencies

In order to use jwt-cpp you need the following tools.

* libcrypto (openssl or compatible)
* libssl-dev (for the header files)
* a compiler supporting at least c++11
* basic stl support

In order to build the test cases you also need

* gtest
* pthread

## Troubleshooting

See the [FAQs](docs/faqs.md) for tips.

## Conference Coverage

[![CppCon](https://img.youtube.com/vi/Oq4NW5idmiI/0.jpg)](https://www.youtube.com/watch?v=Oq4NW5idmiI)
