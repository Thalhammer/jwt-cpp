# Frequently Asked Questions

## The generated JWT token can be decoded, is this correct and secure?

This is the expected behaviour. While the integrity of tokens is ensured by the generated/verified hash,
the contents of the token are only **encoded and not encrypted**. This means you can be sure the token
has not been modified by an unauthorized party, but you should not store confidential information in it. 
Anyone with access to the token can read all the claims you put into it. They can however not modify
them unless they have the (private or symetric) key used to generate the token. If you need to put
confidential information into it, current industry recommends generating a random id and store the data on your
server, using the id to look it up whenever you need.

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
