#if !__has_include(<wolfssl/ssl.h>)
#error "missing wolfSSL's SSL header!"
#endif

// See https://github.com/Thalhammer/jwt-cpp/pull/352
#ifndef EXTERNAL_OPTS_OPENVPN
#error "missing wolfSSL's OPENSSL_EXTRA macro!"
#endif

#include "jwt-cpp/jwt.h"

#include <wolfssl/ssl.h>

int main() {
	wolfSSL_library_init();
	jwt::date date;
	return 0;
}
