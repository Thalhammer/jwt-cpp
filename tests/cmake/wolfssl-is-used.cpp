#if !__has_include(<wolfssl/ssl.h>)
#error "missing wolfSSL's SSL header!
#endif

#include <wolfssl/ssl.h>

#include "jwt-cpp/jwt.h"

int main() {
	wolfSSL_library_init();
	jwt::date date;
	return 0;
}
