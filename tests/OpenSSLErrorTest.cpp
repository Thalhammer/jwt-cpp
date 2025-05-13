#ifdef __linux__ // None of this stuff is going to work outside of linux!

#ifndef HUNTER_ENABLED // Static linking (which hunter always? does) breaks the tests (duplicate definition), so skip them

#include "jwt-cpp/jwt.h"
#include <gtest/gtest.h>

#include <dlfcn.h>
// TODO: Figure out why the tests fail on older openssl versions
#ifndef JWT_OPENSSL_1_0_0 // It fails on < 1.1 but no idea why.
// LibreSSL has different return codes but was already outside of the effective scope

/**
 * ============ Beginning of black magic ===============
 * We mock out a couple of openssl functions.
 * We can do this because the current executable take precedence while linking.
 * Once it is running and we want normal behaviour, we query the original method using dlsym.
 */
static uint64_t fail_BIO_new = 0;
static uint64_t fail_PEM_read_bio_X509 = 0;
static uint64_t fail_X509_get_pubkey = 0;
static uint64_t fail_PEM_write_bio_PUBKEY = 0;
static uint64_t fail_PEM_write_bio_cert = 0;
static uint64_t fail_BIO_ctrl = 0;
#define fail_BIO_get_mem_data fail_BIO_ctrl
static uint64_t fail_BIO_write = 0;
static uint64_t fail_PEM_read_bio_PUBKEY = 0;
static uint64_t fail_PEM_read_bio_PrivateKey = 0;
#if !defined(LIBWOLFSSL_VERSION_HEX) || LIBWOLFSSL_VERSION_HEX > 0x05007000
static uint64_t fail_HMAC = 0;
#endif
static uint64_t fail_EVP_MD_CTX_new = 0;
static uint64_t fail_EVP_DigestInit = 0;
static uint64_t fail_EVP_DigestUpdate = 0;
static uint64_t fail_EVP_DigestFinal = 0;
static uint64_t fail_EVP_SignFinal = 0;
static uint64_t fail_EVP_VerifyFinal = 0;
#ifdef JWT_OPENSSL_3_0
static uint64_t fail_EVP_PKEY_public_check = 0;
static uint64_t fail_EVP_PKEY_private_check = 0;
static uint64_t fail_EVP_PKEY_CTX_new_from_pkey = 0;
#else
static uint64_t fail_EC_KEY_check_key = 0;
static uint64_t fail_EVP_PKEY_get1_EC_KEY = 0;
#endif
static uint64_t fail_ECDSA_SIG_new = 0;
static uint64_t fail_EVP_DigestSignInit = 0;
static uint64_t fail_EVP_DigestSign = 0;
static uint64_t fail_EVP_DigestVerifyInit = 0;
static uint64_t fail_EVP_DigestVerify = 0;
static uint64_t fail_EVP_DigestSignFinal = 0;
static uint64_t fail_EVP_DigestVerifyFinal = 0;
static uint64_t fail_d2i_ECDSA_SIG = 0;
static uint64_t fail_i2d_ECDSA_SIG = 0;
#ifdef JWT_OPENSSL_3_0
static uint64_t fail_OSSL_PARAM_BLD_new = 0;
static uint64_t fail_OSSL_PARAM_BLD_push_BN = 0;
static uint64_t fail_OSSL_PARAM_BLD_push_utf8_string = 0;
static uint64_t fail_OSSL_PARAM_BLD_push_octet_string = 0;
static uint64_t fail_OSSL_PARAM_BLD_to_param = 0;
static uint64_t fail_EVP_PKEY_CTX_new_from_name = 0;
static uint64_t fail_EVP_PKEY_fromdata_init = 0;
static uint64_t fail_EVP_PKEY_fromdata = 0;
#else
static uint64_t fail_PEM_write_bio_RSA_PUBKEY = 0;
static uint64_t fail_RSA_set0_key = 0;
static uint64_t fail_PEM_write_bio_EC_PUBKEY = 0;
static uint64_t fail_EC_GROUP_new_by_curve_name = 0;
static uint64_t fail_EC_POINT_new = 0;
static uint64_t fail_EC_POINT_set_affine_coordinates_GFp = 0;
static uint64_t fail_EC_KEY_new = 0;
#ifndef LIBWOLFSSL_VERSION_HEX
static uint64_t fail_EC_KEY_set_group = 0;
#endif
static uint64_t fail_EC_KEY_set_public_key = 0;
#endif

#ifdef LIBWOLFSSL_VERSION_HEX
#define SYMBOL_NAME(s) ("wolfSSL_" s)
#else
#define SYMBOL_NAME(s) (s)
#endif

BIO* BIO_new(const BIO_METHOD* type) {
	static BIO* (*origMethod)(const BIO_METHOD*) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("BIO_new"));
	bool fail = fail_BIO_new & 1;
	fail_BIO_new = fail_BIO_new >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(type);
}

X509* PEM_read_bio_X509(BIO* bp, X509** x, pem_password_cb* cb, void* u) {
	static X509* (*origMethod)(BIO * bp, X509 * *x, pem_password_cb * cb, void* u) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("PEM_read_bio_X509"));
	bool fail = fail_PEM_read_bio_X509 & 1;
	fail_PEM_read_bio_X509 = fail_PEM_read_bio_X509 >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(bp, x, cb, u);
}

EVP_PKEY* X509_get_pubkey(X509* x) {
	static EVP_PKEY* (*origMethod)(X509*) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("X509_get_pubkey"));
	bool fail = fail_X509_get_pubkey & 1;
	fail_X509_get_pubkey = fail_X509_get_pubkey >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(x);
}

#ifdef JWT_OPENSSL_3_0
#define OPENSSL_CONST const
#else
#define OPENSSL_CONST
#endif

int PEM_write_bio_PUBKEY(BIO* bp, OPENSSL_CONST EVP_PKEY* x) {
	static int (*origMethod)(BIO * bp, OPENSSL_CONST EVP_PKEY * x) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("PEM_write_bio_PUBKEY"));
	bool fail = fail_PEM_write_bio_PUBKEY & 1;
	fail_PEM_write_bio_PUBKEY = fail_PEM_write_bio_PUBKEY >> 1;
	if (fail)
		return 0;
	else
		return origMethod(bp, x);
}

int PEM_write_bio_X509(BIO* bp, OPENSSL_CONST X509* x) {
	static int (*origMethod)(BIO * bp, OPENSSL_CONST X509 * x) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("PEM_write_bio_X509"));
	bool fail = fail_PEM_write_bio_cert & 1;
	fail_PEM_write_bio_cert = fail_PEM_write_bio_cert >> 1;
	if (fail)
		return 0;
	else
		return origMethod(bp, x);
}

long BIO_ctrl(BIO* bp, int cmd, long larg, void* parg) {
	static long (*origMethod)(BIO * bp, int cmd, long larg, void* parg) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("BIO_ctrl"));
	bool fail = fail_BIO_ctrl & 1;
	fail_BIO_ctrl = fail_BIO_ctrl >> 1;
	if (fail)
		return 0;
	else
		return origMethod(bp, cmd, larg, parg);
}

int BIO_write(BIO* b, const void* data, int dlen) {
	static int (*origMethod)(BIO * b, const void* data, int dlen) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("BIO_write"));
	bool fail = fail_BIO_write & 1;
	fail_BIO_write = fail_BIO_write >> 1;
	if (fail)
		return 0;
	else
		return origMethod(b, data, dlen);
}

EVP_PKEY* PEM_read_bio_PUBKEY(BIO* bp, EVP_PKEY** x, pem_password_cb* cb, void* u) {
	static EVP_PKEY* (*origMethod)(BIO * bp, EVP_PKEY * *x, pem_password_cb * cb, void* u) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("PEM_read_bio_PUBKEY"));
	bool fail = fail_PEM_read_bio_PUBKEY & 1;
	fail_PEM_read_bio_PUBKEY = fail_PEM_read_bio_PUBKEY >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(bp, x, cb, u);
}

EVP_PKEY* PEM_read_bio_PrivateKey(BIO* bp, EVP_PKEY** x, pem_password_cb* cb, void* u) {
	static EVP_PKEY* (*origMethod)(BIO * bp, EVP_PKEY * *x, pem_password_cb * cb, void* u) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("PEM_read_bio_PrivateKey"));
	bool fail = fail_PEM_read_bio_PrivateKey & 1;
	fail_PEM_read_bio_PrivateKey = fail_PEM_read_bio_PrivateKey >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(bp, x, cb, u);
}

#if !defined(LIBWOLFSSL_VERSION_HEX) || LIBWOLFSSL_VERSION_HEX > 0x05007000
/* wolfSSL definition collides. Fixed after 5.7.0 */
unsigned char* HMAC(const EVP_MD* evp_md, const void* key, int key_len, const unsigned char* d, size_t n,
					unsigned char* md, unsigned int* md_len) {
	static unsigned char* (*origMethod)(const EVP_MD* evp_md, const void* key, int key_len, const unsigned char* d,
										size_t n, unsigned char* md, unsigned int* md_len) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("HMAC"));
	bool fail = fail_HMAC & 1;
	fail_HMAC = fail_HMAC >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(evp_md, key, key_len, d, n, md, md_len);
}
#endif

EVP_MD_CTX* EVP_MD_CTX_new(void) {
	static EVP_MD_CTX* (*origMethod)(void) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_MD_CTX_new"));
	bool fail = fail_EVP_MD_CTX_new & 1;
	fail_EVP_MD_CTX_new = fail_EVP_MD_CTX_new >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod();
}

int EVP_DigestSignFinal(EVP_MD_CTX* ctx, unsigned char* sigret, size_t* siglen) {
	static int (*origMethod)(EVP_MD_CTX * ctx, unsigned char* sigret, size_t* siglen) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_DigestSignFinal"));
	bool fail = fail_EVP_DigestSignFinal & 1;
	fail_EVP_DigestSignFinal = fail_EVP_DigestSignFinal >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx, sigret, siglen);
}

int EVP_DigestInit(EVP_MD_CTX* ctx, const EVP_MD* type) {
	static int (*origMethod)(EVP_MD_CTX * ctx, const EVP_MD* type) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_DigestInit"));
	bool fail = fail_EVP_DigestInit & 1;
	fail_EVP_DigestInit = fail_EVP_DigestInit >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx, type);
}

int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt) {
	static int (*origMethod)(EVP_MD_CTX * ctx, const void* d, size_t cnt) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_DigestUpdate"));
	bool fail = fail_EVP_DigestUpdate & 1;
	fail_EVP_DigestUpdate = fail_EVP_DigestUpdate >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx, d, cnt);
}

int EVP_DigestFinal(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s) {
	static int (*origMethod)(EVP_MD_CTX * ctx, unsigned char* md, unsigned int* s) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_DigestFinal"));
	bool fail = fail_EVP_DigestFinal & 1;
	fail_EVP_DigestFinal = fail_EVP_DigestFinal >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx, md, s);
}

int EVP_SignFinal(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s, EVP_PKEY* pkey) {
	static int (*origMethod)(EVP_MD_CTX * ctx, unsigned char* md, unsigned int* s, EVP_PKEY* pkey) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_SignFinal"));
	bool fail = fail_EVP_SignFinal & 1;
	fail_EVP_SignFinal = fail_EVP_SignFinal >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx, md, s, pkey);
}

int EVP_VerifyFinal(EVP_MD_CTX* ctx, const unsigned char* sigbuf, unsigned int siglen, EVP_PKEY* pkey) {
	static int (*origMethod)(EVP_MD_CTX * ctx, const unsigned char* sigbuf, unsigned int siglen, EVP_PKEY* pkey) =
		nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_VerifyFinal"));
	bool fail = fail_EVP_VerifyFinal & 1;
	fail_EVP_VerifyFinal = fail_EVP_VerifyFinal >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx, sigbuf, siglen, pkey);
}

#ifdef JWT_OPENSSL_3_0
int EVP_PKEY_public_check(EVP_PKEY_CTX* ctx) {
	static int (*origMethod)(EVP_PKEY_CTX * ctx) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_PKEY_public_check"));
	bool fail = fail_EVP_PKEY_public_check & 1;
	fail_EVP_PKEY_public_check = fail_EVP_PKEY_public_check >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx);
}

int EVP_PKEY_private_check(EVP_PKEY_CTX* ctx) {
	static int (*origMethod)(EVP_PKEY_CTX * ctx) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_PKEY_private_check"));
	bool fail = fail_EVP_PKEY_private_check & 1;
	fail_EVP_PKEY_private_check = fail_EVP_PKEY_private_check >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx);
}

EVP_PKEY_CTX* EVP_PKEY_CTX_new_from_pkey(OSSL_LIB_CTX* libctx, EVP_PKEY* pkey, const char* propquery) {
	static EVP_PKEY_CTX* (*origMethod)(OSSL_LIB_CTX * libctx, EVP_PKEY * pkey, const char* propquery) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_PKEY_CTX_new_from_pkey"));
	bool fail = fail_EVP_PKEY_CTX_new_from_pkey & 1;
	fail_EVP_PKEY_CTX_new_from_pkey = fail_EVP_PKEY_CTX_new_from_pkey >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(libctx, pkey, propquery);
}

#else
int EC_KEY_check_key(const EC_KEY* key) {
	static int (*origMethod)(const EC_KEY* key) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EC_KEY_check_key"));
	bool fail = fail_EC_KEY_check_key & 1;
	fail_EC_KEY_check_key = fail_EC_KEY_check_key >> 1;
	if (fail)
		return 0;
	else
		return origMethod(key);
}

EC_KEY* EVP_PKEY_get1_EC_KEY(EVP_PKEY* pkey) {
	static EC_KEY* (*origMethod)(EVP_PKEY * pkey) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_PKEY_get1_EC_KEY"));
	bool fail = fail_EVP_PKEY_get1_EC_KEY & 1;
	fail_EVP_PKEY_get1_EC_KEY = fail_EVP_PKEY_get1_EC_KEY >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(pkey);
}
#endif

ECDSA_SIG* ECDSA_SIG_new(void) {
	static ECDSA_SIG* (*origMethod)() = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("ECDSA_SIG_new"));
	bool fail = fail_ECDSA_SIG_new & 1;
	fail_ECDSA_SIG_new = fail_ECDSA_SIG_new >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod();
}

int EVP_DigestSignInit(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const EVP_MD* type, ENGINE* e, EVP_PKEY* pkey) {
	static int (*origMethod)(EVP_MD_CTX * ctx, EVP_PKEY_CTX * *pctx, const EVP_MD* type, ENGINE* e, EVP_PKEY* pkey) =
		nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_DigestSignInit"));
	bool fail = fail_EVP_DigestSignInit & 1;
	fail_EVP_DigestSignInit = fail_EVP_DigestSignInit >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx, pctx, type, e, pkey);
}

int EVP_DigestSign(EVP_MD_CTX* ctx, unsigned char* sigret, size_t* siglen, const unsigned char* tbs, size_t tbslen) {
	static int (*origMethod)(EVP_MD_CTX * ctx, unsigned char* sigret, size_t* siglen, const unsigned char* tbs,
							 size_t tbslen) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_DigestSign"));
	bool fail = fail_EVP_DigestSign & 1;
	fail_EVP_DigestSign = fail_EVP_DigestSign >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx, sigret, siglen, tbs, tbslen);
}

int EVP_DigestVerifyInit(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const EVP_MD* type, ENGINE* e, EVP_PKEY* pkey) {
	static int (*origMethod)(EVP_MD_CTX * ctx, EVP_PKEY_CTX * *pctx, const EVP_MD* type, ENGINE* e, EVP_PKEY* pkey) =
		nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_DigestVerifyInit"));
	bool fail = fail_EVP_DigestVerifyInit & 1;
	fail_EVP_DigestVerifyInit = fail_EVP_DigestVerifyInit >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx, pctx, type, e, pkey);
}

int EVP_DigestVerify(EVP_MD_CTX* ctx, unsigned char* sigret, size_t* siglen, const unsigned char* tbs, size_t tbslen) {
	static int (*origMethod)(EVP_MD_CTX * ctx, unsigned char* sigret, size_t* siglen, const unsigned char* tbs,
							 size_t tbslen) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_DigestVerify"));
	bool fail = fail_EVP_DigestVerify & 1;
	fail_EVP_DigestVerify = fail_EVP_DigestVerify >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx, sigret, siglen, tbs, tbslen);
}

int EVP_DigestVerifyFinal(EVP_MD_CTX* ctx, const unsigned char* sigret, size_t siglen) {
	static int (*origMethod)(EVP_MD_CTX * ctx, const unsigned char* sigret, size_t siglen) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_DigestVerifyFinal"));
	bool fail = fail_EVP_DigestVerifyFinal & 1;
	fail_EVP_DigestVerifyFinal = fail_EVP_DigestVerifyFinal >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx, sigret, siglen);
}

int i2d_ECDSA_SIG(const ECDSA_SIG* sig, unsigned char** ppout) {
	static int (*origMethod)(const ECDSA_SIG* sig, unsigned char** ppout) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("i2d_ECDSA_SIG"));
	bool fail = fail_i2d_ECDSA_SIG & 1;
	fail_i2d_ECDSA_SIG = fail_i2d_ECDSA_SIG >> 1;
	if (fail)
		return -1;
	else
		return origMethod(sig, ppout);
}

ECDSA_SIG* d2i_ECDSA_SIG(ECDSA_SIG** psig, const unsigned char** ppin, long len) {
	static ECDSA_SIG* (*origMethod)(ECDSA_SIG * *psig, const unsigned char** ppin, long len) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("d2i_ECDSA_SIG"));
	bool fail = fail_d2i_ECDSA_SIG & 1;
	fail_d2i_ECDSA_SIG = fail_d2i_ECDSA_SIG >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(psig, ppin, len);
}

#ifdef JWT_OPENSSL_3_0
OSSL_PARAM_BLD* OSSL_PARAM_BLD_new() {
	static OSSL_PARAM_BLD* (*origMethod)() = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("OSSL_PARAM_BLD_new"));
	bool fail = fail_OSSL_PARAM_BLD_new & 1;
	fail_OSSL_PARAM_BLD_new = fail_OSSL_PARAM_BLD_new >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod();
}

int OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD* bld, const char* key, const BIGNUM* bn) {
	static int (*origMethod)(OSSL_PARAM_BLD * bld, const char* key, const BIGNUM* bn) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("OSSL_PARAM_BLD_push_BN"));
	bool fail = fail_OSSL_PARAM_BLD_push_BN & 1;
	fail_OSSL_PARAM_BLD_push_BN = fail_OSSL_PARAM_BLD_push_BN >> 1;
	if (fail)
		return 0;
	else
		return origMethod(bld, key, bn);
}

int OSSL_PARAM_BLD_push_utf8_string(OSSL_PARAM_BLD* bld, const char* key, const char* buf, size_t bsize) {
	static int (*origMethod)(OSSL_PARAM_BLD * bld, const char* key, const char* buf, size_t bsize) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("OSSL_PARAM_BLD_push_utf8_string"));
	bool fail = fail_OSSL_PARAM_BLD_push_utf8_string & 1;
	fail_OSSL_PARAM_BLD_push_utf8_string = fail_OSSL_PARAM_BLD_push_utf8_string >> 1;
	if (fail)
		return 0;
	else
		return origMethod(bld, key, buf, bsize);
}

int OSSL_PARAM_BLD_push_octet_string(OSSL_PARAM_BLD* bld, const char* key, const void* buf, size_t bsize) {
	static int (*origMethod)(OSSL_PARAM_BLD * bld, const char* key, const void* buf, size_t bsize) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("OSSL_PARAM_BLD_push_octet_string"));
	bool fail = fail_OSSL_PARAM_BLD_push_octet_string & 1;
	fail_OSSL_PARAM_BLD_push_octet_string = fail_OSSL_PARAM_BLD_push_octet_string >> 1;
	if (fail)
		return 0;
	else
		return origMethod(bld, key, buf, bsize);
}

OSSL_PARAM* OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD* bld) {
	static OSSL_PARAM* (*origMethod)(OSSL_PARAM_BLD * bld) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("OSSL_PARAM_BLD_to_param"));
	bool fail = fail_OSSL_PARAM_BLD_to_param & 1;
	fail_OSSL_PARAM_BLD_to_param = fail_OSSL_PARAM_BLD_to_param >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(bld);
}

EVP_PKEY_CTX* EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX* libctx, const char* name, const char* propquery) {
	static EVP_PKEY_CTX* (*origMethod)(OSSL_LIB_CTX * libctx, const char* name, const char* propquery) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_PKEY_CTX_new_from_name"));
	bool fail = fail_EVP_PKEY_CTX_new_from_name & 1;
	fail_EVP_PKEY_CTX_new_from_name = fail_EVP_PKEY_CTX_new_from_name >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(libctx, name, propquery);
}

int EVP_PKEY_fromdata_init(EVP_PKEY_CTX* ctx) {
	static int (*origMethod)(EVP_PKEY_CTX * ctx) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_PKEY_fromdata_init"));
	bool fail = fail_EVP_PKEY_fromdata_init & 1;
	fail_EVP_PKEY_fromdata_init = fail_EVP_PKEY_fromdata_init >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx);
}

int EVP_PKEY_fromdata(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey, int selection, OSSL_PARAM params[]) {
	static int (*origMethod)(EVP_PKEY_CTX * ctx, EVP_PKEY * *ppkey, int selection, OSSL_PARAM params[]) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EVP_PKEY_fromdata"));
	bool fail = fail_EVP_PKEY_fromdata & 1;
	fail_EVP_PKEY_fromdata = fail_EVP_PKEY_fromdata >> 1;
	if (fail)
		return 0;
	else
		return origMethod(ctx, ppkey, selection, params);
}
#else
int PEM_write_bio_RSA_PUBKEY(BIO* bp, RSA* x) {
	static int (*origMethod)(BIO * bp, RSA * x) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("PEM_write_bio_RSA_PUBKEY"));
	bool fail = fail_PEM_write_bio_RSA_PUBKEY & 1;
	fail_PEM_write_bio_RSA_PUBKEY = fail_PEM_write_bio_RSA_PUBKEY >> 1;
	if (fail)
		return 0;
	else
		return origMethod(bp, x);
}

int RSA_set0_key(RSA* r, BIGNUM* n, BIGNUM* e, BIGNUM* d) {
	static int (*origMethod)(RSA * r, BIGNUM * n, BIGNUM * e, BIGNUM * d) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("RSA_set0_key"));
	bool fail = fail_RSA_set0_key & 1;
	fail_RSA_set0_key = fail_RSA_set0_key >> 1;
	if (fail)
		return 0;
	else
		return origMethod(r, n, e, d);
}

int PEM_write_bio_EC_PUBKEY(BIO* bp, EC_KEY* x) {
	static int (*origMethod)(BIO * bp, EC_KEY * x) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("PEM_write_bio_EC_PUBKEY"));
	bool fail = fail_PEM_write_bio_EC_PUBKEY & 1;
	fail_PEM_write_bio_EC_PUBKEY = fail_PEM_write_bio_EC_PUBKEY >> 1;
	if (fail)
		return 0;
	else
		return origMethod(bp, x);
}

EC_GROUP* EC_GROUP_new_by_curve_name(int nid) {
	static EC_GROUP* (*origMethod)(int nid) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EC_GROUP_new_by_curve_name"));
	bool fail = fail_EC_GROUP_new_by_curve_name & 1;
	fail_EC_GROUP_new_by_curve_name = fail_EC_GROUP_new_by_curve_name >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(nid);
}

EC_POINT* EC_POINT_new(const EC_GROUP* group) {
	static EC_POINT* (*origMethod)(const EC_GROUP* group) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EC_POINT_new"));
	bool fail = fail_EC_POINT_new & 1;
	fail_EC_POINT_new = fail_EC_POINT_new >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod(group);
}

int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP* group, EC_POINT* point, const BIGNUM* x, const BIGNUM* y,
										BN_CTX* ctx) {
	static int (*origMethod)(const EC_GROUP* group, EC_POINT* point, const BIGNUM* x, const BIGNUM* y, BN_CTX* ctx) =
		nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EC_POINT_set_affine_coordinates_GFp"));
	bool fail = fail_EC_POINT_set_affine_coordinates_GFp & 1;
	fail_EC_POINT_set_affine_coordinates_GFp = fail_EC_POINT_set_affine_coordinates_GFp >> 1;
	if (fail)
		return 0;
	else
		return origMethod(group, point, x, y, ctx);
}

EC_KEY* EC_KEY_new() {
	static EC_KEY* (*origMethod)() = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EC_KEY_new"));
	bool fail = fail_EC_KEY_new & 1;
	fail_EC_KEY_new = fail_EC_KEY_new >> 1;
	if (fail)
		return nullptr;
	else
		return origMethod();
}

#ifndef LIBWOLFSSL_VERSION_HEX
int EC_KEY_set_group(EC_KEY* eckey, const EC_GROUP* group) {
	static int (*origMethod)(EC_KEY * eckey, const EC_GROUP* group) = nullptr;
	if (origMethod == nullptr) origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EC_KEY_set_group"));
	bool fail = fail_EC_KEY_set_group & 1;
	fail_EC_KEY_set_group = fail_EC_KEY_set_group >> 1;
	if (fail)
		return 0;
	else
		return origMethod(eckey, group);
}
#endif

int EC_KEY_set_public_key(EC_KEY* eckey, const EC_POINT* pub) {
	static int (*origMethod)(EC_KEY * eckey, const EC_POINT* pub) = nullptr;
	if (origMethod == nullptr)
		origMethod = (decltype(origMethod))dlsym(RTLD_NEXT, SYMBOL_NAME("EC_KEY_set_public_key"));
	bool fail = fail_EC_KEY_set_public_key & 1;
	fail_EC_KEY_set_public_key = fail_EC_KEY_set_public_key >> 1;
	if (fail)
		return 0;
	else
		return origMethod(eckey, pub);
}
#endif

/**
 * =========== End of black magic ============
 */

inline namespace test_keys {
	extern std::string rsa_priv_key;
	extern std::string rsa_pub_key;
	extern std::string rsa_pub_key_invalid;
	extern std::string rsa512_priv_key;
	extern std::string rsa512_pub_key;
	extern std::string rsa512_pub_key_invalid;
	extern std::string ecdsa256_certificate;
	extern std::string ecdsa256_priv_key;
	extern std::string ecdsa256_pub_key;
	extern std::string ecdsa256_pub_key_invalid;
	extern std::string ecdsa384_priv_key;
	extern std::string ecdsa384_pub_key;
	extern std::string ecdsa384_pub_key_invalid;
	extern std::string ecdsa521_priv_key;
	extern std::string ecdsa521_pub_key;
	extern std::string ecdsa521_pub_key_invalid;
	extern std::string sample_cert;
	extern std::string sample_cert_base64_der;
	extern std::string sample_cert_pubkey;
	extern std::string ed25519_priv_key;
	extern std::string ed25519_pub_key;
	extern std::string ed25519_pub_key_invalid;
	extern std::string ed25519_certificate;
	extern std::string ed25519_certificate_base64_der;
	extern std::string ed448_priv_key;
	extern std::string ed448_pub_key;
	extern std::string ed448_pub_key_invalid;
} // namespace test_keys

TEST(OpenSSLErrorTest, ExtractPubkeyFromCertReference) {
	std::error_code ec;
	auto res = jwt::helper::extract_pubkey_from_cert(sample_cert, "", ec);
	ASSERT_EQ(res, sample_cert_pubkey);
	ASSERT_FALSE(!(!ec));
	ASSERT_EQ(ec.value(), 0);
}

#if !defined(LIBWOLFSSL_VERSION_HEX) || LIBWOLFSSL_VERSION_HEX >= 0x05007000
/* Older versions of wolfSSL output different PEM encoding */
TEST(OpenSSLErrorTest, ConvertCertBase64DerToPemReference) {
	std::error_code ec;
	auto res = jwt::helper::convert_base64_der_to_pem(sample_cert_base64_der, ec);
	ASSERT_EQ(res, sample_cert);
	ASSERT_FALSE(!(!ec));
	ASSERT_EQ(ec.value(), 0);
}
#endif

#ifndef LIBWOLFSSL_VERSION_HEX /* wolfSSL: limited ed support in compatibility layer */
TEST(OpenSSLErrorTest, ConvertEcdsaCertBase64DerToPemReference) {
	std::error_code ec;
	auto res = jwt::helper::convert_base64_der_to_pem(ed25519_certificate_base64_der, ec);
	ASSERT_EQ(res, ed25519_certificate);
	ASSERT_FALSE(!(!ec));
	ASSERT_EQ(ec.value(), 0);
}
#endif

struct multitest_entry {
	uint64_t* fail_mask_ptr;
	uint64_t fail_bitmask;
	std::error_code expected_ec;
};

template<typename Func>
void run_multitest(const std::vector<multitest_entry>& mapping, Func fn) {
	for (auto& e : mapping) {
		std::error_code ec;
		*e.fail_mask_ptr = e.fail_bitmask;
		try {
			fn(ec);
		} catch (...) {
			*e.fail_mask_ptr = 0;
			throw;
		}
		*e.fail_mask_ptr = 0;
		ASSERT_EQ(ec, e.expected_ec);
	}
}

TEST(OpenSSLErrorTest, ExtractPubkeyFromCert) {
	std::vector<multitest_entry> mapping{{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
										 {&fail_PEM_read_bio_X509, 1, jwt::error::rsa_error::cert_load_failed},
										 {&fail_X509_get_pubkey, 1, jwt::error::rsa_error::get_key_failed},
										 {&fail_PEM_write_bio_PUBKEY, 1, jwt::error::rsa_error::write_key_failed},
#ifndef LIBWOLFSSL_VERSION_HEX /* wolfSSL does not use BIO_ctrl in BIO_get_mem_data */
										 {&fail_BIO_ctrl, 1, jwt::error::rsa_error::convert_to_pem_failed}
#endif
	};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::helper::extract_pubkey_from_cert(sample_cert, "");
			FAIL(); // Should never reach this
		} catch (const jwt::error::rsa_exception& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, ExtractPubkeyFromCertErrorCode) {
	std::vector<multitest_entry> mapping{{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
										 {&fail_PEM_read_bio_X509, 1, jwt::error::rsa_error::cert_load_failed},
										 {&fail_X509_get_pubkey, 1, jwt::error::rsa_error::get_key_failed},
										 {&fail_PEM_write_bio_PUBKEY, 1, jwt::error::rsa_error::write_key_failed},
#ifndef LIBWOLFSSL_VERSION_HEX /* wolfSSL does not use BIO_ctrl in BIO_get_mem_data */
										 {&fail_BIO_ctrl, 1, jwt::error::rsa_error::convert_to_pem_failed}
#endif
	};

	run_multitest(mapping, [](std::error_code& ec) {
		auto res = jwt::helper::extract_pubkey_from_cert(sample_cert, "", ec);
		ASSERT_EQ(res, "");
	});
}

TEST(OpenSSLErrorTest, CreateRsaPublicKeyFromComponents) {
	std::vector<multitest_entry> mapping{
		{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
#ifndef LIBWOLFSSL_VERSION_HEX
		{&fail_BIO_get_mem_data, 1, jwt::error::rsa_error::convert_to_pem_failed},
#endif
#ifdef JWT_OPENSSL_3_0
		{&fail_PEM_write_bio_PUBKEY, 1, jwt::error::rsa_error::load_key_bio_write},
		{&fail_OSSL_PARAM_BLD_new, 1, jwt::error::rsa_error::create_context_failed},
		{&fail_OSSL_PARAM_BLD_push_BN, 1, jwt::error::rsa_error::set_rsa_failed},
		{&fail_OSSL_PARAM_BLD_to_param, 1, jwt::error::rsa_error::set_rsa_failed},
		{&fail_EVP_PKEY_CTX_new_from_name, 1, jwt::error::rsa_error::create_context_failed},
		{&fail_EVP_PKEY_fromdata_init, 1, jwt::error::rsa_error::cert_load_failed},
		{&fail_EVP_PKEY_fromdata, 1, jwt::error::rsa_error::cert_load_failed}
#else
		{&fail_PEM_write_bio_RSA_PUBKEY, 1, jwt::error::rsa_error::load_key_bio_write},
		{&fail_RSA_set0_key, 1, jwt::error::rsa_error::set_rsa_failed}
#endif
	};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::helper::create_public_key_from_rsa_components(
				"pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-"
				"3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--"
				"hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_"
				"lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_"
				"HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w",
				"AQAB");
			FAIL(); // Should never reach this
		} catch (const jwt::error::rsa_exception& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, CreateRsaPublicKeyFromComponentsErrorCode) {
	std::vector<multitest_entry> mapping{
		{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
#ifndef LIBWOLFSSL_VERSION_HEX
		{&fail_BIO_get_mem_data, 1, jwt::error::rsa_error::convert_to_pem_failed},
#endif
#ifdef JWT_OPENSSL_3_0
		{&fail_PEM_write_bio_PUBKEY, 1, jwt::error::rsa_error::load_key_bio_write},
		{&fail_OSSL_PARAM_BLD_new, 1, jwt::error::rsa_error::create_context_failed},
		{&fail_OSSL_PARAM_BLD_push_BN, 1, jwt::error::rsa_error::set_rsa_failed},
		{&fail_OSSL_PARAM_BLD_to_param, 1, jwt::error::rsa_error::set_rsa_failed},
		{&fail_EVP_PKEY_CTX_new_from_name, 1, jwt::error::rsa_error::create_context_failed},
		{&fail_EVP_PKEY_fromdata_init, 1, jwt::error::rsa_error::cert_load_failed},
		{&fail_EVP_PKEY_fromdata, 1, jwt::error::rsa_error::cert_load_failed}
#else
		{&fail_PEM_write_bio_RSA_PUBKEY, 1, jwt::error::rsa_error::load_key_bio_write},
		{&fail_RSA_set0_key, 1, jwt::error::rsa_error::set_rsa_failed}
#endif
	};

	run_multitest(mapping, [](std::error_code& ec) {
		auto res = jwt::helper::create_public_key_from_rsa_components(
			"pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-"
			"3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_"
			"lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_"
			"HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w",
			"AQAB", ec);
		ASSERT_EQ(res, "");
	});
}

TEST(OpenSSLErrorTest, CreateEcPublicKeyFromComponents) {
	std::vector<multitest_entry> mapping{
		{&fail_BIO_new, 1, jwt::error::ecdsa_error::create_mem_bio_failed},
#ifndef LIBWOLFSSL_VERSION_HEX
		{&fail_BIO_get_mem_data, 1, jwt::error::ecdsa_error::convert_to_pem_failed},
#endif
#ifdef JWT_OPENSSL_3_0
		{&fail_PEM_write_bio_PUBKEY, 1, jwt::error::ecdsa_error::load_key_bio_write},
		{&fail_OSSL_PARAM_BLD_new, 1, jwt::error::ecdsa_error::create_context_failed},
		{&fail_OSSL_PARAM_BLD_push_utf8_string, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
		{&fail_OSSL_PARAM_BLD_push_octet_string, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
		{&fail_OSSL_PARAM_BLD_to_param, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
		{&fail_EVP_PKEY_CTX_new_from_name, 1, jwt::error::ecdsa_error::create_context_failed},
		{&fail_EVP_PKEY_fromdata_init, 1, jwt::error::ecdsa_error::cert_load_failed},
		{&fail_EVP_PKEY_fromdata, 1, jwt::error::ecdsa_error::cert_load_failed}
#else
		{&fail_PEM_write_bio_EC_PUBKEY, 1, jwt::error::ecdsa_error::load_key_bio_write},
		{&fail_EC_GROUP_new_by_curve_name, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
		{&fail_EC_POINT_new, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
		{&fail_EC_POINT_set_affine_coordinates_GFp, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
		{&fail_EC_KEY_new, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
#ifndef LIBWOLFSSL_VERSION_HEX
		{&fail_EC_KEY_set_group, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
#endif
		{&fail_EC_KEY_set_public_key, 1, jwt::error::ecdsa_error::set_ecdsa_failed}
#endif
	};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::helper::create_public_key_from_ec_components(
				"P-384", "0uQ1-1P_wmhOuYvVtTogHOSBLC05IvK7L6sTPIX8Dl4Bg9nhC3v_FsgifjnXnijU",
				"xVJSyWa9SuxwBonUhg6SiCEv-ixb74hjDesC4D7OwllVcnkDJmOy_NMx4N7yDPJp");
			FAIL(); // Should never reach this
		} catch (const jwt::error::ecdsa_exception& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, CreateEcPublicKeyFromComponentsErrorCode) {
	std::vector<multitest_entry> mapping{
		{&fail_BIO_new, 1, jwt::error::ecdsa_error::create_mem_bio_failed},
#ifndef LIBWOLFSSL_VERSION_HEX
		{&fail_BIO_get_mem_data, 1, jwt::error::ecdsa_error::convert_to_pem_failed},
#endif
#ifdef JWT_OPENSSL_3_0
		{&fail_PEM_write_bio_PUBKEY, 1, jwt::error::ecdsa_error::load_key_bio_write},
		{&fail_OSSL_PARAM_BLD_new, 1, jwt::error::ecdsa_error::create_context_failed},
		{&fail_OSSL_PARAM_BLD_push_utf8_string, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
		{&fail_OSSL_PARAM_BLD_push_octet_string, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
		{&fail_OSSL_PARAM_BLD_to_param, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
		{&fail_EVP_PKEY_CTX_new_from_name, 1, jwt::error::ecdsa_error::create_context_failed},
		{&fail_EVP_PKEY_fromdata_init, 1, jwt::error::ecdsa_error::cert_load_failed},
		{&fail_EVP_PKEY_fromdata, 1, jwt::error::ecdsa_error::cert_load_failed}
#else
		{&fail_PEM_write_bio_EC_PUBKEY, 1, jwt::error::ecdsa_error::load_key_bio_write},
		{&fail_EC_GROUP_new_by_curve_name, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
		{&fail_EC_POINT_new, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
		{&fail_EC_POINT_set_affine_coordinates_GFp, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
		{&fail_EC_KEY_new, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
#ifndef LIBWOLFSSL_VERSION_HEX
		{&fail_EC_KEY_set_group, 1, jwt::error::ecdsa_error::set_ecdsa_failed},
#endif
		{&fail_EC_KEY_set_public_key, 1, jwt::error::ecdsa_error::set_ecdsa_failed}
#endif
	};

	run_multitest(mapping, [](std::error_code& ec) {
		auto res = jwt::helper::create_public_key_from_ec_components(
			"P-384", "0uQ1-1P_wmhOuYvVtTogHOSBLC05IvK7L6sTPIX8Dl4Bg9nhC3v_FsgifjnXnijU",
			"xVJSyWa9SuxwBonUhg6SiCEv-ixb74hjDesC4D7OwllVcnkDJmOy_NMx4N7yDPJp", ec);
		ASSERT_EQ(res, "");
	});
}

TEST(OpenSSLErrorTest, ConvertCertBase64DerToPem) {
	std::vector<multitest_entry> mapping{{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
										 {&fail_PEM_write_bio_cert, 1, jwt::error::rsa_error::write_cert_failed},
#ifndef LIBWOLFSSL_VERSION_HEX /* wolfSSL does not use BIO_ctrl in BIO_get_mem_data */
										 {&fail_BIO_ctrl, 1, jwt::error::rsa_error::convert_to_pem_failed}
#endif
	};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::helper::convert_base64_der_to_pem(sample_cert_base64_der);
			FAIL(); // Should never reach this
		} catch (const jwt::error::rsa_exception& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, ConvertEcdsaCertBase64DerToPem) {
	std::vector<multitest_entry> mapping{{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
#ifndef LIBWOLFSSL_VERSION_HEX
										 {&fail_PEM_write_bio_cert, 1, jwt::error::rsa_error::write_cert_failed},
										 {&fail_BIO_ctrl, 1, jwt::error::rsa_error::convert_to_pem_failed}
#else
										 {&fail_PEM_write_bio_cert, 1, jwt::error::rsa_error::create_mem_bio_failed},
										 {&fail_BIO_ctrl, 1, jwt::error::rsa_error::create_mem_bio_failed}
#endif
	};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::helper::convert_base64_der_to_pem(ed25519_certificate_base64_der);
			FAIL(); // Should never reach this
		} catch (const jwt::error::rsa_exception& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, ConvertCertBase64DerToPemErrorCode) {
	std::vector<multitest_entry> mapping{{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
										 {&fail_PEM_write_bio_cert, 1, jwt::error::rsa_error::write_cert_failed},
#ifndef LIBWOLFSSL_VERSION_HEX /* wolfSSL does not use BIO_ctrl in BIO_get_mem_data */
										 {&fail_BIO_ctrl, 1, jwt::error::rsa_error::convert_to_pem_failed}
#endif
	};

	run_multitest(mapping, [](std::error_code& ec) {
		auto res = jwt::helper::convert_base64_der_to_pem(sample_cert_base64_der, ec);
		ASSERT_EQ(res, "");
	});
}

TEST(OpenSSLErrorTest, LoadPublicKeyFromStringReference) {
	auto res = jwt::helper::load_public_key_from_string(rsa_pub_key, "");
	ASSERT_TRUE(res);
}

TEST(OpenSSLErrorTest, LoadPublicKeyFromStringReferenceWithEcCert) {
	auto res = jwt::helper::load_public_key_from_string(ecdsa256_pub_key, "");
	ASSERT_TRUE(res);
}

TEST(OpenSSLErrorTest, LoadPublicKeyFromStringReferenceWithEcCertAndErr) {
	auto res = jwt::helper::load_public_key_from_string<jwt::error::ecdsa_error>(ecdsa256_pub_key, "");
	ASSERT_TRUE(res);
}

TEST(OpenSSLErrorTest, LoadPublicKeyFromString) {
	std::vector<multitest_entry> mapping{{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
										 {&fail_BIO_write, 1, jwt::error::rsa_error::load_key_bio_write},
										 {&fail_PEM_read_bio_PUBKEY, 1, jwt::error::rsa_error::load_key_bio_read}};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::helper::load_public_key_from_string(rsa_pub_key, "");
			FAIL(); // Should never reach this
		} catch (const jwt::error::rsa_exception& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, LoadPublicKeyFromStringWithEc) {
	std::vector<multitest_entry> mapping{{&fail_BIO_new, 1, jwt::error::ecdsa_error::create_mem_bio_failed},
										 {&fail_BIO_write, 1, jwt::error::ecdsa_error::load_key_bio_write},
										 {&fail_PEM_read_bio_PUBKEY, 1, jwt::error::ecdsa_error::load_key_bio_read}};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::helper::load_public_key_from_string<jwt::error::ecdsa_error>(ecdsa256_pub_key, "");
			FAIL(); // Should never reach this
		} catch (const jwt::error::ecdsa_exception& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, LoadPublicKeyFromStringErrorCode) {
	std::vector<multitest_entry> mapping{{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
										 {&fail_BIO_write, 1, jwt::error::rsa_error::load_key_bio_write},
										 {&fail_PEM_read_bio_PUBKEY, 1, jwt::error::rsa_error::load_key_bio_read}};

	run_multitest(mapping, [](std::error_code& ec) {
		auto res = jwt::helper::load_public_key_from_string(rsa_pub_key, "", ec);
		ASSERT_FALSE(res);
	});
}

TEST(OpenSSLErrorTest, LoadPublicKeyCertFromStringReference) {
	auto res = jwt::helper::load_public_key_from_string(sample_cert, "");
	ASSERT_TRUE(res);
}

TEST(OpenSSLErrorTest, LoadPublicKeyCertFromString) {
	std::vector<multitest_entry> mapping {
		{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
#ifndef LIBWOLFSSL_VERSION_HEX
			{&fail_BIO_get_mem_data, 1, jwt::error::rsa_error::convert_to_pem_failed},
#endif
#if defined(LIBWOLFSSL_VERSION_HEX)
			{&fail_BIO_write, 1, jwt::error::rsa_error::write_key_failed},
#elif !defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x3050300fL
			{&fail_BIO_write, 1, jwt::error::rsa_error::load_key_bio_write},
#else
			{&fail_BIO_write, 1, jwt::error::rsa_error::write_key_failed},
#endif
		{
			&fail_PEM_read_bio_PUBKEY, 1, jwt::error::rsa_error::load_key_bio_read
		}
	};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::helper::load_public_key_from_string(sample_cert, "");
			FAIL(); // Should never reach this
		} catch (const jwt::error::rsa_exception& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, LoadPublicKeyCertFromStringErrorCode) {
	std::vector<multitest_entry> mapping {
		{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
#ifndef LIBWOLFSSL_VERSION_HEX
			{&fail_BIO_get_mem_data, 1, jwt::error::rsa_error::convert_to_pem_failed}, // extract_pubkey_from_cert
#endif
#if defined(LIBWOLFSSL_VERSION_HEX)
			{&fail_BIO_write, 1, jwt::error::rsa_error::write_key_failed},
#elif !defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x3050300fL
			{&fail_BIO_write, 1, jwt::error::rsa_error::load_key_bio_write},
#else
			{&fail_BIO_write, 1, jwt::error::rsa_error::write_key_failed},
#endif
		{
			&fail_PEM_read_bio_PUBKEY, 1, jwt::error::rsa_error::load_key_bio_read
		}
	};

	run_multitest(mapping, [](std::error_code& ec) {
		auto res = jwt::helper::load_public_key_from_string(sample_cert, "", ec);
		ASSERT_FALSE(res);
	});
}

TEST(OpenSSLErrorTest, LoadPrivateKeyFromStringReference) {
	auto res = jwt::helper::load_private_key_from_string(rsa_priv_key, "");
	ASSERT_TRUE(res);
}

TEST(OpenSSLErrorTest, LoadPrivateKeyFromString) {
	std::vector<multitest_entry> mapping{{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
										 {&fail_BIO_write, 1, jwt::error::rsa_error::load_key_bio_write},
										 {&fail_PEM_read_bio_PrivateKey, 1, jwt::error::rsa_error::load_key_bio_read}};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::helper::load_private_key_from_string(rsa_priv_key, "");
			FAIL(); // Should never reach this
		} catch (const jwt::error::rsa_exception& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, LoadPrivateKeyFromStringErrorCode) {
	std::vector<multitest_entry> mapping{{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
										 {&fail_BIO_write, 1, jwt::error::rsa_error::load_key_bio_write},
										 {&fail_PEM_read_bio_PrivateKey, 1, jwt::error::rsa_error::load_key_bio_read}};

	run_multitest(mapping, [](std::error_code& ec) {
		auto res = jwt::helper::load_private_key_from_string(rsa_priv_key, "", ec);
		ASSERT_FALSE(res);
	});
}

#if !defined(LIBWOLFSSL_VERSION_HEX) || LIBWOLFSSL_VERSION_HEX > 0x05007000
TEST(OpenSSLErrorTest, HMACSign) {
	std::string const token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";

	auto verify = jwt::verify().allow_algorithm(jwt::algorithm::hs256{"secret"}).with_issuer("auth0");

	auto decoded_token = jwt::decode(token);
	std::vector<multitest_entry> mapping{{&fail_HMAC, 1, jwt::error::signature_generation_error::hmac_failed}};

	run_multitest(mapping, [&](std::error_code& ec) { verify.verify(decoded_token, ec); });
}
#endif

TEST(OpenSSLErrorTest, RS256Reference) {
	jwt::algorithm::rs256 alg{rsa_pub_key, rsa_priv_key};
	std::error_code ec;
	auto res = alg.sign("testdata", ec);
	ASSERT_EQ(jwt::base::encode<jwt::alphabet::base64>(res),
			  "oCJUeLmIKKVVE/UWhEL/Malx0l9TCoXWNAS2z9o8ZYNaS4POIeadZWeUbLdICx3SCJCnGRwL8JkAmYx1wexT2QGuVXXAtZvRu8ceyuQy"
			  "AhzGkI9HdADu5YAJsUaLknDUV5hmundXQY8lhwQnKFXW0rl0H8DoFiPQErFmcKI6PA9NVGK/LSiqHqesNeg0wqCTxMmeT6pqI7FH9fDO"
			  "CaBpwUJ4t5aKoytQ75t13OfUM7tfLlVkFZtI3RndhivxLA5d4Elt/Gv3RhDu6Eiom5NZ/pwRvP26Sox+FWapz3DGCil70H1iGSYu8ENa"
			  "afUBCGGhT4sk7kl7zS6XiEpMobLq3A==");
	ASSERT_FALSE(!(!ec));

	alg.verify("testdata", res, ec);
	ASSERT_FALSE(!(!ec));
}

TEST(OpenSSLErrorTest, RS256SignErrorCode) {
	jwt::algorithm::rs256 alg{rsa_pub_key, rsa_priv_key};
	std::vector<multitest_entry> mapping{
		{&fail_EVP_MD_CTX_new, 1, jwt::error::signature_generation_error::create_context_failed},
		{&fail_EVP_DigestInit, 1, jwt::error::signature_generation_error::signinit_failed},
		{&fail_EVP_DigestUpdate, 1, jwt::error::signature_generation_error::signupdate_failed},
		{&fail_EVP_SignFinal, 1, jwt::error::signature_generation_error::signfinal_failed}};

	run_multitest(mapping, [&alg](std::error_code& ec) {
		auto res = alg.sign("testdata", ec);
		ASSERT_EQ(res, "");
	});
}

TEST(OpenSSLErrorTest, RS256VerifyErrorCode) {
	jwt::algorithm::rs256 alg{rsa_pub_key, rsa_priv_key};
	auto signature = jwt::base::decode<jwt::alphabet::base64>(
		"oCJUeLmIKKVVE/UWhEL/Malx0l9TCoXWNAS2z9o8ZYNaS4POIeadZWeUbLdICx3SCJCnGRwL8JkAmYx1wexT2QGuVXXAtZvRu8ceyuQy"
		"AhzGkI9HdADu5YAJsUaLknDUV5hmundXQY8lhwQnKFXW0rl0H8DoFiPQErFmcKI6PA9NVGK/LSiqHqesNeg0wqCTxMmeT6pqI7FH9fDO"
		"CaBpwUJ4t5aKoytQ75t13OfUM7tfLlVkFZtI3RndhivxLA5d4Elt/Gv3RhDu6Eiom5NZ/pwRvP26Sox+FWapz3DGCil70H1iGSYu8ENa"
		"afUBCGGhT4sk7kl7zS6XiEpMobLq3A==");
	std::vector<multitest_entry> mapping{
		{&fail_EVP_MD_CTX_new, 1, jwt::error::signature_verification_error::create_context_failed},
		{&fail_EVP_DigestInit, 1, jwt::error::signature_verification_error::verifyinit_failed},
		{&fail_EVP_DigestUpdate, 1, jwt::error::signature_verification_error::verifyupdate_failed},
		{&fail_EVP_VerifyFinal, 1, jwt::error::signature_verification_error::verifyfinal_failed}};

	run_multitest(mapping, [&alg, &signature](std::error_code& ec) { alg.verify("testdata", signature, ec); });
}

TEST(OpenSSLErrorTest, LoadECDSAPrivateKeyFromString) {
	std::vector<multitest_entry> mapping{
		{&fail_BIO_new, 1, jwt::error::ecdsa_error::create_mem_bio_failed},
		{&fail_BIO_write, 1, jwt::error::ecdsa_error::load_key_bio_write},
		{&fail_PEM_read_bio_PrivateKey, 1, jwt::error::ecdsa_error::load_key_bio_read},
#ifdef JWT_OPENSSL_3_0
		{&fail_EVP_PKEY_private_check, 1, jwt::error::ecdsa_error::invalid_key},
		{&fail_EVP_PKEY_CTX_new_from_pkey, 1, jwt::error::ecdsa_error::create_context_failed},
#else
		{&fail_EC_KEY_check_key, 1, jwt::error::ecdsa_error::invalid_key},
		{&fail_EVP_PKEY_get1_EC_KEY, 1, jwt::error::ecdsa_error::invalid_key},
#endif
	};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::algorithm::es256 alg{"", ecdsa256_priv_key};
			FAIL(); // Should never reach this
		} catch (const std::system_error& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, LoadECDSAPublicKeyFromString) {
	std::vector<multitest_entry> mapping{
		{&fail_BIO_new, 1, jwt::error::ecdsa_error::create_mem_bio_failed},
		{&fail_BIO_write, 1, jwt::error::ecdsa_error::load_key_bio_write},
		{&fail_PEM_read_bio_PUBKEY, 1, jwt::error::ecdsa_error::load_key_bio_read},
#ifdef JWT_OPENSSL_3_0
		{&fail_EVP_PKEY_public_check, 1, jwt::error::ecdsa_error::invalid_key},
		{&fail_EVP_PKEY_CTX_new_from_pkey, 1, jwt::error::ecdsa_error::create_context_failed},
#else
		{&fail_EC_KEY_check_key, 1, jwt::error::ecdsa_error::invalid_key},
		{&fail_EVP_PKEY_get1_EC_KEY, 1, jwt::error::ecdsa_error::invalid_key},
#endif
	};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::algorithm::es256 alg{ecdsa256_pub_key, ""};
			FAIL(); // Should never reach this
		} catch (const std::system_error& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, ECDSACertificate) {
	std::vector<multitest_entry> mapping {
		{&fail_BIO_new, 1, jwt::error::ecdsa_error::create_mem_bio_failed},
#if defined(LIBWOLFSSL_VERSION_HEX)
			{&fail_BIO_write, 1, jwt::error::ecdsa_error::write_key_failed},
#elif !defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x3050300fL
			{&fail_BIO_write, 1, jwt::error::ecdsa_error::load_key_bio_write},
#else
			{&fail_BIO_write, 1, jwt::error::ecdsa_error::write_key_failed},
#endif
			{&fail_PEM_read_bio_PUBKEY, 1, jwt::error::ecdsa_error::load_key_bio_read},
			// extract_pubkey_from_cert
			{&fail_BIO_new, 2, jwt::error::ecdsa_error::create_mem_bio_failed},
			{&fail_PEM_read_bio_X509, 1, jwt::error::ecdsa_error::cert_load_failed},
			{&fail_X509_get_pubkey, 1, jwt::error::ecdsa_error::get_key_failed},
			{&fail_PEM_write_bio_PUBKEY, 1, jwt::error::ecdsa_error::write_key_failed},
#ifndef LIBWOLFSSL_VERSION_HEX /* wolfSSL does not use BIO_ctrl in BIO_get_mem_data */
		{
			&fail_BIO_ctrl, 1, jwt::error::ecdsa_error::convert_to_pem_failed
		}
#endif
	};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::algorithm::es256 alg{ecdsa256_certificate};
			FAIL(); // Should never reach this
		} catch (const std::system_error& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, ES256Reference) {
	jwt::algorithm::es256 alg{ecdsa256_pub_key, ecdsa256_priv_key};
	std::error_code ec;
	auto res = alg.sign("testdata", ec);
	ASSERT_FALSE(!(!ec));

	alg.verify("testdata", res, ec);
	ASSERT_FALSE(!(!ec));
}

TEST(OpenSSLErrorTest, ES256SignErrorCode) {
	jwt::algorithm::es256 alg{ecdsa256_pub_key, ecdsa256_priv_key};
	std::vector<multitest_entry> mapping {
		{&fail_EVP_MD_CTX_new, 1, jwt::error::signature_generation_error::create_context_failed},
			{&fail_EVP_DigestSignInit, 1, jwt::error::signature_generation_error::signinit_failed},
			{&fail_EVP_DigestUpdate, 1, jwt::error::signature_generation_error::digestupdate_failed},
			{&fail_EVP_DigestSignFinal, 1, jwt::error::signature_generation_error::signfinal_failed},
			{&fail_EVP_DigestSignFinal, 2, jwt::error::signature_generation_error::signfinal_failed},
#if !defined(LIBWOLFSSL_VERSION_HEX) || LIBWOLFSSL_VERSION_HEX < 0x05007000
			{&fail_d2i_ECDSA_SIG, 1, jwt::error::signature_generation_error::signature_decoding_failed},
#else
			{&fail_d2i_ECDSA_SIG, 1, jwt::error::signature_generation_error::signfinal_failed},
#endif
	};

	run_multitest(mapping, [&alg](std::error_code& ec) {
		auto res = alg.sign("testdata", ec);
		ASSERT_EQ(res, "");
	});
}

TEST(OpenSSLErrorTest, ES256VerifyErrorCode) {
	jwt::algorithm::es256 alg{ecdsa256_pub_key, ecdsa256_priv_key};
	auto signature = jwt::base::decode<jwt::alphabet::base64>(
		"aC/NqyHfPw5FDA0yRAnrbkrAlXjsr0obRkCg/HgP+77QYJrAg6YKkKoJwMXjUX8fQrxXKTN7em5L9dtmOep37Q==");
	std::vector<multitest_entry> mapping{
		{&fail_EVP_MD_CTX_new, 1, jwt::error::signature_verification_error::create_context_failed},
		{&fail_EVP_DigestVerifyInit, 1, jwt::error::signature_verification_error::verifyinit_failed},
		{&fail_EVP_DigestUpdate, 1, jwt::error::signature_verification_error::verifyupdate_failed},
		{&fail_EVP_DigestVerifyFinal, 1, jwt::error::signature_verification_error::invalid_signature},
		{&fail_ECDSA_SIG_new, 1, jwt::error::signature_verification_error::create_context_failed},
		{&fail_i2d_ECDSA_SIG, 1, jwt::error::signature_verification_error::signature_encoding_failed},
		{&fail_i2d_ECDSA_SIG, 2, jwt::error::signature_verification_error::signature_encoding_failed},
	};

	run_multitest(mapping, [&alg, &signature](std::error_code& ec) { alg.verify("testdata", signature, ec); });
}

TEST(OpenSSLErrorTest, PS256Reference) {
	jwt::algorithm::ps256 alg{rsa_pub_key, rsa_priv_key};
	std::error_code ec;
	auto res = alg.sign("testdata", ec);
	ASSERT_FALSE(!(!ec));

	alg.verify("testdata", res, ec);
	ASSERT_FALSE(!(!ec));
}

TEST(OpenSSLErrorTest, PS256SignErrorCode) {
	jwt::algorithm::ps256 alg{rsa_pub_key, rsa_priv_key};
	std::vector<multitest_entry> mapping{
		{&fail_EVP_MD_CTX_new, 1, jwt::error::signature_generation_error::create_context_failed},
		{&fail_EVP_DigestSignInit, 1, jwt::error::signature_generation_error::signinit_failed},
		{&fail_EVP_DigestUpdate, 1, jwt::error::signature_generation_error::digestupdate_failed},
		{&fail_EVP_DigestSignFinal, 1, jwt::error::signature_generation_error::signfinal_failed},
		//TODO: EVP_PKEY_CTX_set_rsa_padding, EVP_PKEY_CTX_set_rsa_pss_saltlen
	};

	run_multitest(mapping, [&alg](std::error_code& ec) {
		auto res = alg.sign("testdata", ec);
		ASSERT_EQ(res, "");
	});
}

TEST(OpenSSLErrorTest, PS256VerifyErrorCode) {
	jwt::algorithm::ps256 alg{rsa_pub_key, rsa_priv_key};
	std::string signature =
		"LMiWCiW0a/"
		"mbU6LK8EZaDQ6TGisqfD+LF46zUbzjhFt02J9yVuf3ZDNTdRgLKKP8nCJUx0SN+5CS2YD268Ioxau5bWs49RVCxtID5DcRpJlSo+Vk+"
		"dCmwxhQWHX8HNh3o7kBK5H8fLeTeupuSov+0hH3+"
		"GRrYJqZvCdbcadi6amNKCfeIl6a5mp2VCM55NsPoRxsmSzc1G7AHWb1ckOCsm3KY5BL6B074bHgoqO3yaLlKWLAcy4OYyRpJ/wnZQ9PPrhwdq/"
		"B59uW3x1QUCKYKgZeqZOoqIP1YgLwvEpPtXYutQCFr4eBKgV7vdtE0wgHR43ka16fi5L4SyaZv53NCg==";
	signature = jwt::base::decode<jwt::alphabet::base64>(signature);
	std::vector<multitest_entry> mapping{
		{&fail_EVP_MD_CTX_new, 1, jwt::error::signature_verification_error::create_context_failed},
		{&fail_EVP_DigestVerifyInit, 1, jwt::error::signature_verification_error::verifyinit_failed},
		{&fail_EVP_DigestUpdate, 1, jwt::error::signature_verification_error::verifyupdate_failed},
		{&fail_EVP_DigestVerifyFinal, 1, jwt::error::signature_verification_error::verifyfinal_failed},
	};

	run_multitest(mapping, [&alg, &signature](std::error_code& ec) { alg.verify("testdata", signature, ec); });
}

#if !defined(JWT_OPENSSL_1_0_0) && !defined(JWT_OPENSSL_1_1_0)
TEST(OpenSSLErrorTest, EdDSAKey) {
	std::vector<multitest_entry> mapping{
		// load_private_key_from_string
		{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
		{&fail_BIO_write, 1, jwt::error::rsa_error::load_key_bio_write},
		{&fail_PEM_read_bio_PrivateKey, 1, jwt::error::rsa_error::load_key_bio_read},
		// load_public_key_from_string
		{&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
		{&fail_BIO_write, 1, jwt::error::rsa_error::load_key_bio_write},
		// { &fail_PEM_read_bio_PUBKEY, 1, jwt::error::rsa_error::load_key_bio_read }
	};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::algorithm::ed25519 alg{ed25519_pub_key, ed25519_priv_key};
			FAIL(); // Should never reach this
		} catch (const std::system_error& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, EdDSACertificate) {
	std::vector<multitest_entry> mapping{// load_public_key_from_string
										 {&fail_BIO_new, 1, jwt::error::rsa_error::create_mem_bio_failed},
										 {&fail_BIO_write, 1, jwt::error::rsa_error::load_key_bio_write},
										 {&fail_PEM_read_bio_PUBKEY, 1, jwt::error::rsa_error::load_key_bio_read},
										 // extract_pubkey_from_cert
										 {&fail_BIO_new, 2, jwt::error::rsa_error::create_mem_bio_failed},
										 {&fail_PEM_read_bio_X509, 1, jwt::error::rsa_error::cert_load_failed},
										 {&fail_X509_get_pubkey, 1, jwt::error::rsa_error::get_key_failed},
										 {&fail_PEM_write_bio_PUBKEY, 1, jwt::error::rsa_error::write_key_failed},
										 {&fail_BIO_ctrl, 1, jwt::error::rsa_error::convert_to_pem_failed}};

	run_multitest(mapping, [](std::error_code& ec) {
		try {
			jwt::algorithm::ed25519 alg{ed25519_certificate};
			FAIL(); // Should never reach this
		} catch (const std::system_error& e) { ec = e.code(); }
	});
}

TEST(OpenSSLErrorTest, Ed25519Reference) {
	// No keys should throw
	ASSERT_THROW(jwt::algorithm::ed25519("", ""), jwt::error::ecdsa_exception);

	jwt::algorithm::ed25519 alg{ed25519_pub_key, ed25519_priv_key};
	std::error_code ec;
	auto res = alg.sign("testdata", ec);
	ASSERT_FALSE(!(!ec));

	alg.verify("testdata", res, ec);
	ASSERT_FALSE(!(!ec));
}

TEST(OpenSSLErrorTest, Ed25519SignErrorCode) {
	jwt::algorithm::ed25519 alg{ed25519_pub_key, ed25519_priv_key};
	std::vector<multitest_entry> mapping{
		{&fail_EVP_MD_CTX_new, 1, jwt::error::signature_generation_error::create_context_failed},
		{&fail_EVP_DigestSignInit, 1, jwt::error::signature_generation_error::signinit_failed},
		{&fail_EVP_DigestSign, 1, jwt::error::signature_generation_error::signfinal_failed}};

	run_multitest(mapping, [&alg](std::error_code& ec) {
		auto res = alg.sign("testdata", ec);
		ASSERT_EQ(res, "");
	});
}

TEST(OpenSSLErrorTest, Ed25519VerifyErrorCode) {
	jwt::algorithm::ed25519 alg{ed25519_pub_key, ed25519_priv_key};
	auto signature = jwt::base::decode<jwt::alphabet::base64>(
		"aC/NqyHfPw5FDA0yRAnrbkrAlXjsr0obRkCg/HgP+77QYJrAg6YKkKoJwMXjUX8fQrxXKTN7em5L9dtmOep37Q==");
	std::vector<multitest_entry> mapping{
		{&fail_EVP_MD_CTX_new, 1, jwt::error::signature_verification_error::create_context_failed},
		{&fail_EVP_DigestVerifyInit, 1, jwt::error::signature_verification_error::verifyinit_failed},
		{&fail_EVP_DigestVerify, 1, jwt::error::signature_verification_error::verifyfinal_failed}};

	run_multitest(mapping, [&alg, &signature](std::error_code& ec) { alg.verify("testdata", signature, ec); });
}
#endif
#endif
#endif
#endif
