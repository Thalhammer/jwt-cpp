module;

#ifndef NOMINMAX
#define NOMINMAX 1
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#ifndef JWT_USE_IMPORT_STD
#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cinttypes>
#include <exception>
#include <float.h>
#include <functional>
#include <iomanip>
#include <iterator>
#include <limits>
#include <locale>
#include <locale.h>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>
#include <cwchar>
#else
#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

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

#ifdef JWT_USE_IMPORT_STD
// Keep std private to jwt_cpp. Re-exporting it makes mixed consumers
// (gtest, iostream, third-party JSON headers) collide with the MSVC std module.
import std;
#endif

// Build the public headers in module purview so imported declarations are
// attached to jwt_cpp instead of the global module.
#define JWT_CPP_MODULE_INTERFACE_BUILD 1
export {
#include "jwt-cpp/jwt.h"
}
#undef JWT_CPP_MODULE_INTERFACE_BUILD
