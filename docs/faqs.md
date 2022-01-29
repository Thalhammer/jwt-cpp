# Frequently Asked Questions

## The generated JWT token can be decoded, is this correct and secure?

Yes it is correct, in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) the tokens are defined as being base64 encoded.
This is not a cryptographic hash and can easily be reversed.

This is **not** secure, you should not have any sensitive information in your tokens without extra application logic.

## Can this library encrypt/decrypt claims?

No it does not, see [Issue 115](https://github.com/Thalhammer/jwt-cpp/issues/115) for more details.
More importantly you probably dont want to be using JWTs for anything sensitive. Read [this](https://stackoverflow.com/a/43497242/8480874)
for more.

## Why are my tokens immediately expired?

If you are generating tokens that seem to immediately expire, you are likely not using UTC. Specifically,
if you use `get_time` to get the current time, it likely uses localtime, while this library uses UTC,
which may be why your token is immediately expiring. Please see example above on the right way to use current time.

## Missing \_HMAC and \_EVP_sha256 symbols on Mac

There seems to exists a problem with the included openssl library of MacOS. Make sure you link to one provided by brew.
See [here](https://github.com/Thalhammer/jwt-cpp/issues/6) for more details.

## Building on windows fails with syntax errors

The header `<Windows.h>`, which is often included in windowsprojects, defines macros for MIN and MAX which screw up std::numeric_limits.
See [here](https://github.com/Thalhammer/jwt-cpp/issues/5) for more details. To fix this do one of the following things:

* define NOMINMAX, which suppresses this behaviour
* include this library before you include windows.h
* place `#undef max` and `#undef min` before you include this library
