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

| OpenSSL               | LibreSSL           | wolfSSL        |
| --------------------- | ------------------ | -------------- |
| ![4.1.0][o4.1]        | ![4.4.1][l4.4]     | ![5.9.4][w5.9] |
| ![3.5.5][o3.5] :star: | ![4.2.1][l4.2]     | ![5.7.0][w5.7] |
| ![3.0.19][o3.0]       | ![3.9.2][l3.9]     | ![5.3.0][w5.3] |

> [!NOTE]
> :star: Indicates LTS (Long-Term Support) versions. [OpenSSL versions](https://openssl-library.org/policies/releasestrat/index.html) are supported as follows:
>
> - **3.5.5**: Supported until 2030-04-08 (LTS)
> - **4.1.0**: Supported until 2027-11-23
>
> A complete list of versions tested in the past can be found [on this branch](https://github.com/Thalhammer/jwt-cpp/tree/badges).

[o3.0]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/openssl/3.0.19/shields.json
[o3.5]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/openssl/3.5.5/shields.json
[o4.1]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/openssl/4.1.0/shields.json
[l4.4]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/libressl/4.4.1/shields.json
[l4.2]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/libressl/4.2.1/shields.json
[l3.9]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/libressl/3.9.2/shields.json
[w5.3]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/wolfssl/5.3.0/shields.json
[w5.7]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/wolfssl/5.7.0/shields.json
[w5.9]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Thalhammer/jwt-cpp/badges/wolfssl/5.9.4/shields.json

## Notes

JWT-CPP relies on the OpenSSL API, as a result both LibreSSL and wolfSSL need to include their respective compatibility layers.
Most system already have OpenSSL so it's important to make sure when compiling your application it only includes one. Otherwise you may have missing symbols when linking.
