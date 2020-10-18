# jwt-cpp

[![License Badge](https://img.shields.io/github/license/Thalhammer/jwt-cpp)](https://github.com/Thalhammer/jwt-cpp/blob/master/LICENSE)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/5f7055e294744901991fd0a1620b231d)](https://app.codacy.com/app/Thalhammer/jwt-cpp?utm_source=github.com&utm_medium=referral&utm_content=Thalhammer/jwt-cpp&utm_campaign=Badge_Grade_Settings)
[![Build Status](https://travis-ci.com/Thalhammer/jwt-cpp.svg?branch=master)](https://travis-ci.com/Thalhammer/jwt-cpp)
[![Coverage Status](https://coveralls.io/repos/github/Thalhammer/jwt-cpp/badge.svg?branch=master)](https://coveralls.io/github/Thalhammer/jwt-cpp?branch=master)
[![Documentation Badge](https://img.shields.io/badge/Documentation-master-blue)](https://thalhammer.github.io/jwt-cpp/)
[![Stars Badge](https://img.shields.io/github/stars/Thalhammer/jwt-cpp)](https://github.com/Thalhammer/jwt-cpp/stargazers)

A header only library for creating and validating [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) in C++11. For a great introduction, [read this](https://jwt.io/introduction/)

## Signature algorithms

jwt-cpp supports all algorithms defined by the spec. The modular design of jwt-cpp allows one to add additional algorithms without any problems. If you need any feel free to open a pull request.
For the sake of completeness, here is a list of all supported algorithms:

* HS256
* HS384
* HS512
* RS256
* RS384
* RS512
* ES256
* ES384
* ES512
* PS256
* PS384
* PS512
* EdDSA (Ed25519, Ed448), since 0.5.0

## Overview

Since 0.5.0-rc.0, there is no hard dependency on a JSON library; instead there's a generic `jwt::basic_claim` which is templated around the types required.It requires a traits type, which defines types for a value, object, array, string, number, integer and boolean, as well as methods to translate between them.

```cpp
jwt::basic_claim<my_favorite_json_library_traits> claim(json::object({{"json", true},{"example", 0}}));
```

This allows for complete freedom when picking which libraries you want to use. For more information, [see below](#providing-your-own-json-traits-your-traits)

In order to maintain compatibility, [picojson](https://github.com/kazuho/picojson) is still used to provide a specialized `jwt::claim` along with all helpers. Defining `DISABLE_PICOJSON` will remove this optional dependency.

As for the base64 requirements of JWTs, this libary provides `base.h` with all the required implentation; However base64 implementations are very common, with varying degrees of performance. When providing your own base64 implementation, you can define `DISABLE_BASE64` to remove the jwt-cpp implementation.

### Getting Started

Simple example of decoding a token and printing all claims:

```cpp
#include <jwt-cpp/jwt.h>
#include <iostream>

int main() {
    std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
    auto decoded = jwt::decode(token);

    for(auto& e : decoded.get_payload_claims())
        std::cout << e.first << " = " << e.second << std::endl;
}
```

In order to verify a token you first build a verifier and use it to verify a decoded token.

```cpp
auto verifier = jwt::verify()
    .allow_algorithm(jwt::algorithm::hs256{ "secret" })
    .with_issuer("auth0");

verifier.verify(decoded_token);
```

The created verifier is stateless so you can reuse it for different tokens.

Creating a token (and signing) is equally easy.

```cpp
auto token = jwt::create()
    .set_issuer("auth0")
    .set_type("JWS")
    .set_payload_claim("sample", jwt::claim(std::string("test")))
    .sign(jwt::algorithm::hs256{"secret"});
```

Here is a simple example of creating a token that will expire in one hour:

```cpp
auto token = jwt::create()
    .set_issuer("auth0")
    .set_issued_at(std::chrono::system_clock::now())
    .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
    .sign(jwt::algorithm::hs256{"secret"});
```

> To see more examples working with RSA public and private keys, visit our [examples](https://github.com/Thalhammer/jwt-cpp/tree/master/example)!

### Providing your own JSON Traits

There are several key items that need to be provided to a `jwt::basic_claim` in order for it to be interoptable with you JSON library of choice.

* type specifications
* conversion from genric "value type" to specific
* serialization and parsing

If ever you are not sure, the traits are heavily checked against static asserts to make sure you provide everything that's required.

```cpp
struct my_favorite_json_library_traits {
    // Type Specifications
    using value_type = json; // The generic "value type" implementation, most libraries have one
    using object_type = json::object_t; // The "map type" string to value
    using array_type = json::array_t; // The "list type" array of values
    using string_type = std::string; // The "list of chars", must be a narrow char
    using number_type = double; // The "percision type"
    using integer_type = int64_t; // The "integral type"
    using boolean_type = bool; // The "boolean type"

    // Translation between the implementation notion of type, to the jwt::json::type equivilant
    static jwt::json::type get_type(const value_type &val) {
        using jwt::json::type;

        if (val.type() == json::value_t::object)
            return type::object;
        if (val.type() == json::value_t::array)
            return type::array;
        if (val.type() == json::value_t::string)
            return type::string;
        if (val.type() == json::value_t::number_float)
            return type::number;
        if (val.type() == json::value_t::number_integer)
            return type::integer;
        if (val.type() == json::value_t::boolean)
            return type::boolean;

        throw std::logic_error("invalid type");
    }

    // Conversion from generic value to specific type
    static object_type as_object(const value_type &val);
    static array_type as_array(const value_type &val);
    static string_type as_string(const value_type &val);
    static number_type as_number(const value_type &val);
    static integer_type as_int(const value_type &val);
    static boolean_type as_bool(const value_type &val);

    // serilization and parsing
    static bool parse(value_type &val, string_type str);
    static string_type serialize(const value_type &val);
};
```

## Contributing

If you have an improvement or found a bug feel free to [open an issue](https://github.com/Thalhammer/jwt-cpp/issues/new) or add the change and create a pull request. If you file a bug please make sure to include as much information about your environment (compiler version, etc.) as possible to help reproduce the issue. If you add a new feature please make sure to also include test cases for it.

## Dependencies

In order to use jwt-cpp you need the following tools.

* libcrypto (openssl or compatible)
* libssl-dev (for the header files)
* a compiler supporting at least c++11
* basic stl support

In order to build the test cases you also need

* gtest
* pthread

## Troubleshooting

### Expired tokens

If you are generating tokens that seem to immediately expire, you are likely not using UTC. Specifically,
if you use `get_time` to get the current time, it likely uses localtime, while this library uses UTC,
which may be why your token is immediately expiring. Please see example above on the right way to use current time.

### Missing \_HMAC and \_EVP_sha256 symbols on Mac

There seems to exists a problem with the included openssl library of MacOS. Make sure you link to one provided by brew.
See [here](https://github.com/Thalhammer/jwt-cpp/issues/6) for more details.

### Building on windows fails with syntax errors

The header `<Windows.h>`, which is often included in windowsprojects, defines macros for MIN and MAX which screw up std::numeric_limits.
See [here](https://github.com/Thalhammer/jwt-cpp/issues/5) for more details. To fix this do one of the following things:

* define NOMINMAX, which suppresses this behaviour
* include this library before you include windows.h
* place `#undef max` and `#undef min` before you include this library
