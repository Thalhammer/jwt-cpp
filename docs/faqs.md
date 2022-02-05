# Frequently Asked Questions

## Handling Tokens

### The generated JWT token can be decoded, is this correct and secure?

This is the expected behaviour. While the integrity of tokens is ensured by the generated/verified hash,
the contents of the token are only **encoded and not encrypted**. This means you can be sure the token
has not been modified by an unauthorized party, but you should not store confidential information in it. 
Anyone with access to the token can read all the claims you put into it. They can however not modify
them unless they have the (private or symetric) key used to generate the token. If you need to put
confidential information into it, current industry recommends generating a random id and store the data on your
server, using the id to look it up whenever you need.

### Can this library encrypt/decrypt claims?

No it does not, see [#115](https://github.com/Thalhammer/jwt-cpp/issues/115) for more details.
More importantly you probably dont want to be using JWTs for anything sensitive. Read [this](https://stackoverflow.com/a/43497242/8480874)
for more.

### Why are my tokens immediately expired?

If you are generating tokens that seem to immediately expire, you are likely mixing local time where it is not required. The JWT specification
requires using UTC which this library does.

Here is a simple example of creating a token that will expire in one hour:

```cpp
auto token = jwt::create()
    .set_issued_at(std::chrono::system_clock::now())
    .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
    .sign(jwt::algorithm::hs256{"secret"});
```

### Can you add claims to a signed token?

The signature includes both the header and payload, according to the RFCs... changing the payload would cause a discrepancy.
That should result in the token being rejected. For more details checkout [#194](https://github.com/Thalhammer/jwt-cpp/issues/194).

## Build Issues

### Missing \_HMAC and \_EVP_sha256 symbols on Mac

There seems to exists a problem with the included openssl library of MacOS. Make sure you link to one provided by brew.
See [here](https://github.com/Thalhammer/jwt-cpp/issues/6) for more details.

### Building on windows fails with syntax errors

The header `<Windows.h>`, which is often included in windowsprojects, defines macros for MIN and MAX which screw up std::numeric_limits.
See [here](https://github.com/Thalhammer/jwt-cpp/issues/5) for more details. To fix this do one of the following things:

* define NOMINMAX, which suppresses this behaviour
* include this library before you include windows.h
* place `#undef max` and `#undef min` before you include this library
