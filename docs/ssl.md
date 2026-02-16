# Cryptography Libraries

The underlying cryptography libraries describe [here](../README.md#ssl-compatibility) can be selected when configuring CMake by explicitly setting `JWT_SSL_LIBRARY` to one of three values. The default is to use OpenSSL.

- OpenSSL
- LibreSSL
- wolfSSL

Here's an example:

```sh
cmake . -DJWT_SSL_LIBRARY:STRING=wolfSSL 
```

## Supported Versions

These are the versions which are currently being tested:

| OpenSSL           | LibreSSL       | wolfSSL        |
| ----------------- | -------------- | -------------- |
| ![3.0.19][o3.0]   | ![4.2.1][l4.2] | ![5.1.1][w5.1] |
| ![3.5.5][o3.5] :star: | ![4.1.2][l4.1] | ![5.2.0][w5.2] |
| ![3.6.1][o3.6]    | ![3.9.2][l3.9] | ![5.3.0][w5.3] |

> [!NOTE]
> :star: Indicates LTS (Long-Term Support) versions. [OpenSSL versions](https://openssl-library.org/policies/releasestrat/index.html) are supported as follows:
> - **3.0.19**: Supported until 2026-09-07 (LTS)
> - **3.5.5**: Supported until 2030-04-08 (LTS)
> - **3.6.1**: Supported until 2026-11-01
>
> A complete list of versions tested in the past can be found [here](https://github.com/Thalhammer/jwt-cpp/tree/badges).

[o1.0.2]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/openssl/1.0.2u/shields.json
[o1.1.0]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/openssl/1.1.0i/shields.json
[o1.1.1]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/openssl/1.1.1q/shields.json
[o3.0]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/openssl/3.0.19/shields.json
[o3.5]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/openssl/3.5.5/shields.json
[o3.6]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/openssl/3.6.1/shields.json
[l4.2]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/libressl/4.2.1/shields.json
[l4.1]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/libressl/4.1.2/shields.json
[l3.9]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/libressl/3.9.2/shields.json
[w5.1]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/wolfssl/5.1.1/shields.json
[w5.2]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/wolfssl/5.2.0/shields.json
[w5.3]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/wolfssl/5.3.0/shields.json

## Notes

JWT-CPP relies on the OpenSSL API, as a result both LibreSSL and wolfSSL need to include their respective compatibility layers.
Most system already have OpenSSL so it's important to make sure when compiling your application it only includes one. Otherwise you may have missing symbols when linking.
