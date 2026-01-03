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

#include "jwt-cpp/jwt.h"

export module jwt_cpp;

export using ::operator>>;
export using ::operator<<;

export namespace jwt {
	using jwt::verify;
	using jwt::decode;
	using jwt::create;
	using jwt::claim;
	using jwt::date;
	using jwt::parse_jwk;
	using jwt::parse_jwks;
}

export namespace jwt::algorithm {
	using jwt::algorithm::ecdsa;
	using jwt::algorithm::ed25519;
	using jwt::algorithm::ed448;
	using jwt::algorithm::eddsa;
	using jwt::algorithm::es256;
	using jwt::algorithm::es256k;
	using jwt::algorithm::es384;
	using jwt::algorithm::es512;
	using jwt::algorithm::hmacsha;
	using jwt::algorithm::hs256;
	using jwt::algorithm::hs384;
	using jwt::algorithm::hs512;
	using jwt::algorithm::none;
	using jwt::algorithm::ps256;
	using jwt::algorithm::ps384;
	using jwt::algorithm::ps512;
	using jwt::algorithm::pss;
	using jwt::algorithm::rs256;
	using jwt::algorithm::rs384;
	using jwt::algorithm::rs512;
	using jwt::algorithm::rsa;
}

export namespace jwt::base {
	using jwt::base::encode;
}

export namespace jwt::alphabet {
	using jwt::alphabet::base64url;
}

export namespace jwt::helper {
	using jwt::helper::convert_base64_der_to_pem;
	using jwt::helper::create_public_key_from_rsa_components;
}

export namespace jwt::error {
	using jwt::error::make_error_code;
	using jwt::error::invalid_json_exception;
	using jwt::error::claim_not_present_exception;
	using jwt::error::token_verification_error;
	using jwt::error::token_verification_exception;
	using jwt::error::token_verification_error_category;
}