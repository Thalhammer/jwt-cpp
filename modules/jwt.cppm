module;

#ifndef NOMINMAX
#define NOMINMAX 1
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#endif

export module jwt_cpp;

import std;

#define JWT_CPP_MODULE_INTERFACE_BUILD 1
#include "jwt-cpp/jwt.h"
#undef JWT_CPP_MODULE_INTERFACE_BUILD
