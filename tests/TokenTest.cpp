// Include the generated trait type list for parameterized testing
#include "traits_typelist.h"

#include <gmock/gmock.h>
using ::testing::AnyOf;

template<typename Trait>
class TokenTest : public ::testing::Test {};

TYPED_TEST_SUITE(TokenTest, AllTraitTypes);

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
	extern std::string ed25519_priv_key;
	extern std::string ed25519_pub_key;
	extern std::string ed25519_pub_key_invalid;
	extern std::string ed448_priv_key;
	extern std::string ed448_pub_key;
	extern std::string ed448_pub_key_invalid;
} // namespace test_keys

TYPED_TEST(TokenTest, MissingDot) {
	EXPECT_THROW(jwt::decode<TypeParam>("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJpc3MiOiJhdXRoMCJ9"),
				 std::invalid_argument);
	EXPECT_THROW(jwt::decode<TypeParam>("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0eyJpc3MiOiJhdXRoMCJ9."),
				 std::invalid_argument);
	EXPECT_THROW(jwt::decode<TypeParam>("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0eyJpc3MiOiJhdXRoMCJ9"),
				 std::invalid_argument);
}

TYPED_TEST(TokenTest, InvalidChar) {
	EXPECT_THROW(jwt::decode<TypeParam>("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0().eyJpc3MiOiJhdXRoMCJ9."),
				 std::runtime_error);
}

TYPED_TEST(TokenTest, InvalidJSON) {
	EXPECT_ANY_THROW(jwt::decode<TypeParam>("YXsiYWxnIjoibm9uZSIsInR5cCI6IkpXUyJ9YQ.eyJpc3MiOiJhdXRoMCJ9."));
}

TYPED_TEST(TokenTest, GitHubIssue341) {
	std::string const token =
		"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjYXV0aDAiLCJleHAiOjE3MTMzODgxNjgsInN1YiI6InRlc3RfdXNlciJ9."
		"dlAk0mSWk1Clzfi1PMq7Omxun3EyEqh-AAu-fTkpabA67ZKenawAQhZO8glY93flukpJCqHLVtukaes6ZSOjGw";
	ASSERT_NO_THROW(jwt::decode<TypeParam>(token));
	auto decoded = jwt::decoded_jwt<TypeParam>(token);

	EXPECT_TRUE(decoded.has_algorithm());
	EXPECT_TRUE(decoded.has_type());
	EXPECT_TRUE(decoded.has_issuer());
	EXPECT_TRUE(decoded.has_subject());

	EXPECT_EQ("ES256", decoded.get_algorithm());
	EXPECT_EQ("JWT", decoded.get_type());
	EXPECT_EQ("cauth0", decoded.get_issuer());
	EXPECT_EQ("test_user", decoded.get_subject());
}

TYPED_TEST(TokenTest, DecodeToken) {
	std::string token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
	ASSERT_NO_THROW(jwt::decode<TypeParam>(token));
	auto decoded = jwt::decode<TypeParam>(token);

	EXPECT_TRUE(decoded.has_algorithm());
	EXPECT_TRUE(decoded.has_type());
	EXPECT_FALSE(decoded.has_content_type());
	EXPECT_FALSE(decoded.has_key_id());
	EXPECT_TRUE(decoded.has_issuer());
	EXPECT_FALSE(decoded.has_subject());
	EXPECT_FALSE(decoded.has_audience());
	EXPECT_FALSE(decoded.has_expires_at());
	EXPECT_FALSE(decoded.has_not_before());
	EXPECT_FALSE(decoded.has_issued_at());
	EXPECT_FALSE(decoded.has_id());

	EXPECT_EQ("HS256", decoded.get_algorithm());
	EXPECT_EQ("JWS", decoded.get_type());
	EXPECT_EQ("auth0", decoded.get_issuer());
}

TYPED_TEST(TokenTest, CreateToken) {
	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(jwt::algorithm::none{});
	EXPECT_THAT(token, AnyOf("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJpc3MiOiJhdXRoMCJ9.",
							 "eyJ0eXAiOiJKV1MiLCJhbGciOiJub25lIn0.eyJpc3MiOiJhdXRoMCJ9."));
}

TYPED_TEST(TokenTest, CreateTokenHS256) {
	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(jwt::algorithm::hs256{"secret"});
	EXPECT_THAT(
		token,
		AnyOf("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE",
			  "eyJ0eXAiOiJKV1MiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4cAAvglS11pWWgSYUdrBYT0QbkBbv-LBCbVDBMYan2g"));
}

TYPED_TEST(TokenTest, CreateTokenRS256) {
	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
		jwt::algorithm::rs256(rsa_pub_key, rsa_priv_key, "", ""));

	EXPECT_THAT(token, AnyOf("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9."
							 "VA2i1ui1cnoD6I3wnji1WAVCf29EekysvevGrT2GXqK1dDMc8"
							 "HAZCTQxa1Q8NppnpYV-hlqxh-X3Bb0JOePTGzjynpNZoJh2aHZD-"
							 "GKpZt7OO1Zp8AFWPZ3p8Cahq8536fD8RiBES9jRsvChZvOqA7gMcFc4"
							 "YD0iZhNIcI7a654u5yPYyTlf5kjR97prCf_OXWRn-bYY74zna4p_bP9oWCL4BkaoRcMxi-"
							 "IR7kmVcCnvbYqyIrKloXP2qPO442RBGqU7Ov9"
							 "sGQxiVqtRHKXZR9RbfvjrErY1KGiCp9M5i2bsUHadZEY44FE2jiOmx-uc2z5c05CCXqVSpfCjWbh9gQ",
							 "eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9."
							 "uDKRv4xfFzPDVAQq9OsvJiVBkLFU67rikyKbVzhZd8NVhtI-MCk_"
							 "AnQBU4NXMiKh5G5YrMjgXpPhqVMo8TW6yamkkv2qeJ0YFzEqrNvJYrqtxaHRthtWcNgoF3DflK78DwPuJUZXtzbKE"
							 "Kx6FVRhB2h4yK88ic2Cc5lFKfxDwsNxanm0BtJ2JuS6iOD3JfSjHuL24cGP_"
							 "IiDVpf2LCZcVjmlTBjJ6XrWTBDfM7igxDGQ3lZehE8iu0fvPsELPQQHl6u1uiIm9QEMq9MYF4-"
							 "fv0aEaV2lo6b360kfmY64nBhzfaEisW1ilsrrTHnZWoN5evrDUCYT3bVFSvPlCzS2RA"));
}

TYPED_TEST(TokenTest, CreateTokenEvpPkeyRS256) {
	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
		jwt::algorithm::rsa(jwt::helper::load_private_key_from_string(rsa_priv_key), EVP_sha256, "RS256"));

	EXPECT_THAT(token, AnyOf("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9."
							 "VA2i1ui1cnoD6I3wnji1WAVCf29EekysvevGrT2GXqK1dDMc8"
							 "HAZCTQxa1Q8NppnpYV-hlqxh-X3Bb0JOePTGzjynpNZoJh2aHZD-"
							 "GKpZt7OO1Zp8AFWPZ3p8Cahq8536fD8RiBES9jRsvChZvOqA7gMcFc4"
							 "YD0iZhNIcI7a654u5yPYyTlf5kjR97prCf_OXWRn-bYY74zna4p_bP9oWCL4BkaoRcMxi-"
							 "IR7kmVcCnvbYqyIrKloXP2qPO442RBGqU7Ov9"
							 "sGQxiVqtRHKXZR9RbfvjrErY1KGiCp9M5i2bsUHadZEY44FE2jiOmx-uc2z5c05CCXqVSpfCjWbh9gQ",
							 "eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9."
							 "uDKRv4xfFzPDVAQq9OsvJiVBkLFU67rikyKbVzhZd8NVhtI-MCk_"
							 "AnQBU4NXMiKh5G5YrMjgXpPhqVMo8TW6yamkkv2qeJ0YFzEqrNvJYrqtxaHRthtWcNgoF3DflK78DwPuJUZXtzbKE"
							 "Kx6FVRhB2h4yK88ic2Cc5lFKfxDwsNxanm0BtJ2JuS6iOD3JfSjHuL24cGP_"
							 "IiDVpf2LCZcVjmlTBjJ6XrWTBDfM7igxDGQ3lZehE8iu0fvPsELPQQHl6u1uiIm9QEMq9MYF4-"
							 "fv0aEaV2lo6b360kfmY64nBhzfaEisW1ilsrrTHnZWoN5evrDUCYT3bVFSvPlCzS2RA"));
}

#if !defined(JWT_OPENSSL_1_0_0)
TYPED_TEST(TokenTest, CreateTokenRS256Encrypted) {
	// openssl genrsa -aes256 -out private.pem 2048
	// openssl rsa -in private.pem -pubout -out public.pem
	const std::string rsa_passphrase = "helloworld";
	const std::string rsa_public = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtJWZsTVZxeeYWkSeVPvo
yQtHH6KjJ4HcV6bI7gQQlPjDKzleIuK2bjC9mEv9+ewxL5qoYHm6Q5iYA0tYkHx0
Aa8OkzvmWxIZirDKf6axAlL8xKdDK0HX9/oIam4OR5zw91NcHmEuMgBBu4ILkQfr
qCTETiXVYHHhcnwV6U10/enz8peDxEXo77oeI6CalRmH/g0Oj+S5yTQ3dsz3q8n8
tMHSxy1h3OQcQBZzgB/GiWheSyGyECX+/DqfZnIjb7zJRu8xoQI+qU0UXhntPiV+
ywHCPw0c+rmPgRkALmmUMyZ2sK72QpQjhOL59kAIg2Vz9PdKVLgP+ZW3nAzgrvvG
JwIDAQAB
-----END PUBLIC KEY-----)";
	const std::string rsa_private = R"(-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQeb8/yxYvMn62nkN1
KP7E4gICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEDJ/wKEMBgtyQu+Q
37MgQjIEggTQaH3WnuO47ZAiD5AEnN5vnQrS+ZXprDMLzSpZnVphQJlckgVkGpMu
uMrVANcNNRFYK6WTwXkfqDz+16BlsfEGNENSXm1Db16x+9pU1rnkYPYl5Tupe4Tx
9e6ibHmN8SzNud7eiMCFrQV/xgWvfcfDKR2mksHAQF0XGoWnrB7ZkZmxseLgFzvE
pKnrYYEwUKmYVrtSMe0qqsTk/o5Yq0toxPJ5LYCUhw8NhPOc4YtFV86ol13gwMzF
8qrmsJOT7D4+aERo5QvlVNtVICs5E/Ofaz1CVhmls1WSOq+Ngh1HTBfq10x+XBLO
1SH5e8ExnwYUPO+p54R0x0Z/2Q9HbR5Ws63n50bW9fBAS0efceFW0dGLcbzRgRCQ
aFXzcdkPH0Zs1fLM7upDUMiRJE7KYQsOc5kDFQfGpOiJ6A7IVOdVOQsRkRZkmf+j
+E3U/xV6mN4YRwdJlQgbA+/64NzBySYfEnLFJHPg2+bonx05blyDV4dx2glhsuE7
qtKkcCyV/23MtHQL2DI8kAJpZn0aLrMtShYlCssbBD+H8YoraAf5BA6G1m00wJoc
6DX47Uig5tYV3cUwjv2LVlbczxVzCgyMMUiTn5N9FTv+NKt75+dMcK+wiC8GkrdJ
Ls2omXgJBjCf2cCawdZncYhyk8MxEYeJQygr7Yc2g4RaL6WhgQlkbdi8kamvSDzp
CxzLH9oUAwxI0tOppglJCo1Payjeal1Kw83TO/oXfKtPbkmWzw4e/vGy/hDq44+I
0Xi1lH5/qsFXIRFFERI3S355Yc7y9h71QvSN81kpLxcYfQEcvva7qzDnhJe16Vx1
zmDfjDcqf1Zk85BORk8Rf4PWyFLRhksQUQduVu3U9NwBxwogqoosTNzOQ6s78m0n
piwOPm7rYH7rjWwxtAAHUqESewWRdA+vv7DSL2KcqboYsz8T0q58cotyAWg9LFMl
0DS1hzYV1QK8anWjq44etUfPWSjCSLPcNPKkYn7bnUOUSP3kN9U4o+mLAEoVxtMu
5qii/Dk9fKIzFFKD1CgE5rjtGWwEgd1i8vFpivmIfmsyYJpHZTOxaDh5yf070YuK
2rOHfXTf9foAtvzM6jaGPzzFm376uj5p+byLFjDMvPb4fRZ0P90Wag/8KWV+TBD1
5StfiisyHem5aJjLfXap4FEw0WMUeaxgnvUnjQw9FVtIOpJRSrHq6NWIjPhpVPbO
USIj0NMMYG7sqkwN8OdH8KrjX8QeuO4NEXXEMgPFnlXDbjHz2kX/vuSUxuMbEOa6
T3vB6hAX6xwMgMCBY1vAQl7mmL/vw/vXbSuKv1Ibt2dTb5k4SjtajD23yhwQCZkM
Z0aUpzZ1gr4Wa5Y27l6ss9/U3Tx/7ufI9ogDyeVtHZffhpih7gFiKyENAXOquZHU
n9BK3LDfqRvF0x/anEBQtleLo9srDPRrxWIfQms9vhjJoCY489XfdA2zeYguD8YI
+9BejQXBi2rRct0Fx/6i/NryGk5rAfWHWk8JHqoNXj22k/LluSbykmHuHupSLelx
zbWUDoX0QfmWg+yaMEqvTges4crmbf8aVQohAkCdzAqAwzrT4miRoUQTmkdUPCgP
ixip+DkPtcbSsFjn2bVnknYYluk+Qupw/kWGxyFbvC1sYhn1iNwFv0g=
-----END ENCRYPTED PRIVATE KEY-----)";

	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
		jwt::algorithm::rs256(rsa_public, rsa_private, rsa_passphrase, rsa_passphrase));

	EXPECT_THAT(token, AnyOf("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.HL2mq18xubKWG1j4GZI2DLBi-"
							 "wajNyI9QotK31VjX1pQdfarHr9OsX5qiHydXfPBJSj-O4xIeH92LGslH1Z3rYiEwrq0dN6hr8nFfcBUYHu1nntYe_"
							 "hVFXdx5oK8V427aKPUxlBq8MyOGLYFCXFKYWLinLTCihPHnEV5LFI2HGGtWm-"
							 "S2OlNKawt24qnOhRtwE8QuckfOiiIjCtPH8798cOZzBrsqMdKTYhlFM28dTkejP_AgJUwD6QujSm2is0kAg1_"
							 "SXxKTDSHVlg8irtG9ZQZXcuhaZCieAE1uIlJmKpEg4MUHVfvMsgy0N0p64NOiHa6bQsEb3NFn7UAe55jKQ",
							 "eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9."
							 "euR6TAvNGYyA1yqPa5DcwYhMHO1XhP0Guv4lP4ZDlG0v9gW4jHF8b1pJpfZnbXeUyt6xlJK6B_fe_"
							 "vPJX8h6gkDkX8dywD65ULpsboGUqBkPZmy19cnPaFLsOZud2F_"
							 "WR8demr1I7P0GvClvj1Vc1GLH75htKds9TUsGwCPI4TRY1MTeMdFxkSOaLPMLSgjXtqdk8IDNvvy718COQ3QQ_"
							 "VLeOECeEuVvvAcLIymZVdgmu_VesmoerRqDWQwYUsug8tJYN3QDfzLU4WrGbXXO_1z8t1QzOf5jgzH4IHQGXbRJ-"
							 "5H6oCw3hz5o27RrJW6tTrjLDPELPQq2tOseePqF6w"));
}
#endif

TYPED_TEST(TokenTest, CreateTokenRS512) {
	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
		jwt::algorithm::rs512(rsa512_pub_key, rsa512_priv_key, "", ""));

	EXPECT_THAT(
		token,
		AnyOf("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.GZhnjtsvBl2_KDSxg4JW6xnmNjr2mWhYSZSSQyLKvI0"
			  "TK86sJKchkt_HDy2IC5l5BGRhq_Xv9pHdA1umidQZG3a7gWvHsujqybCBgBraMTd1wJrCl4QxFg2RYHhHbRqb9BnPJgFD_vryd4GB"
			  "hfGgejPBCBlGrQtqFGFdHHOjNHY",
			  "eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.yoJDOjEs1SsuLk5X7QunClqmmcLW8IaoH_"
			  "wmueLlAS87OCDnEsGUosfomktPqBRVbOrTaX_SHDH-7OnpmaNA8gX3xMzAeloZFwuYFcZSwKWtX1e8EtjCUXLYr-"
			  "TReHxeJslf81rLQJBUm1tWFhlorWZ7a8qo_VKoUWteED7M_mA"));
}

TYPED_TEST(TokenTest, CreateTokenPS256) {
	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
		jwt::algorithm::ps256(rsa_pub_key, rsa_priv_key, "", ""));

	// TODO: Find a better way to check if generated signature is valid
	// Can't do simple check for equal since pss adds random salt.
}

TYPED_TEST(TokenTest, CreateTokenPS384) {
	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
		jwt::algorithm::ps384(rsa_pub_key, rsa_priv_key, "", ""));

	// TODO: Find a better way to check if generated signature is valid
	// Can't do simple check for equal since pss adds random salt.
}

TYPED_TEST(TokenTest, CreateTokenPS512) {
	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
		jwt::algorithm::ps512(rsa_pub_key, rsa_priv_key, "", ""));

	// TODO: Find a better way to check if generated signature is valid
	// Can't do simple check for equal since pss adds random salt.
}

TYPED_TEST(TokenTest, CreateTokenES256) {

	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
		jwt::algorithm::es256("", ecdsa256_priv_key, "", ""));

	auto decoded = jwt::decode<TypeParam>(token);

	EXPECT_THROW(jwt::verify<TypeParam>()
					 .allow_algorithm(jwt::algorithm::es256(ecdsa256_pub_key_invalid, "", "", ""))
					 .verify(decoded),
				 jwt::error::signature_verification_exception);
	EXPECT_NO_THROW(
		jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::es256(ecdsa256_pub_key, "", "", "")).verify(decoded));
}

TYPED_TEST(TokenTest, CreateTokenEvpPkeyES256) {

	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(jwt::algorithm::ecdsa(
		jwt::helper::load_private_ec_key_from_string(ecdsa256_priv_key), EVP_sha256, "ES256", 64));

	auto decoded = jwt::decode<TypeParam>(token);

	EXPECT_THROW(jwt::verify<TypeParam>()
					 .allow_algorithm(jwt::algorithm::es256(ecdsa256_pub_key_invalid, "", "", ""))
					 .verify(decoded),
				 jwt::error::signature_verification_exception);
	EXPECT_NO_THROW(
		jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::es256(ecdsa256_pub_key, "", "", "")).verify(decoded));
}

TYPED_TEST(TokenTest, CreateTokenEvpPkeyES256NoPrivate) {
	EXPECT_THROW(
		[]() {
			auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(jwt::algorithm::ecdsa(
				jwt::helper::load_public_ec_key_from_string(ecdsa256_pub_key), EVP_sha256, "ES256", 64));
		}(),
		jwt::error::signature_generation_exception);
}

TYPED_TEST(TokenTest, CreateTokenES256NoPrivate) {
	EXPECT_THROW(
		[]() {
			auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
				jwt::algorithm::es256(ecdsa256_pub_key, "", "", ""));
		}(),
		jwt::error::signature_generation_exception);
}

TYPED_TEST(TokenTest, CreateTokenES384) {

	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
		jwt::algorithm::es384("", ecdsa384_priv_key, "", ""));

	auto decoded = jwt::decode<TypeParam>(token);

	EXPECT_THROW(jwt::verify<TypeParam>()
					 .allow_algorithm(jwt::algorithm::es384(ecdsa384_pub_key_invalid, "", "", ""))
					 .verify(decoded),
				 jwt::error::signature_verification_exception);
	EXPECT_NO_THROW(
		jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::es384(ecdsa384_pub_key, "", "", "")).verify(decoded));
}

TYPED_TEST(TokenTest, CreateTokenES384NoPrivate) {

	EXPECT_THROW(
		[]() {
			auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
				jwt::algorithm::es384(ecdsa384_pub_key, "", "", ""));
		}(),
		jwt::error::signature_generation_exception);
}

TYPED_TEST(TokenTest, CreateTokenES512) {

	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
		jwt::algorithm::es512("", ecdsa521_priv_key, "", ""));

	auto decoded = jwt::decode<TypeParam>(token);

	EXPECT_THROW(jwt::verify<TypeParam>()
					 .allow_algorithm(jwt::algorithm::es512(ecdsa521_pub_key_invalid, "", "", ""))
					 .verify(decoded),
				 jwt::error::signature_verification_exception);
	EXPECT_NO_THROW(
		jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::es512(ecdsa521_pub_key, "", "", "")).verify(decoded));
}

TYPED_TEST(TokenTest, CreateTokenES512NoPrivate) {

	EXPECT_THROW(
		[]() {
			auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
				jwt::algorithm::es512(ecdsa521_pub_key, "", "", ""));
		}(),
		jwt::error::signature_generation_exception);
}

#if !defined(JWT_OPENSSL_1_0_0) && !defined(JWT_OPENSSL_1_1_0)
TYPED_TEST(TokenTest, CreateTokenEd25519) {

	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
		jwt::algorithm::ed25519("", ed25519_priv_key, "", ""));

	auto decoded = jwt::decode<TypeParam>(token);

	EXPECT_THROW(jwt::verify<TypeParam>()
					 .allow_algorithm(jwt::algorithm::ed25519(ed25519_pub_key_invalid, "", "", ""))
					 .verify(decoded),
				 jwt::error::signature_verification_exception);
	EXPECT_NO_THROW(
		jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::ed25519(ed25519_pub_key, "", "", "")).verify(decoded));
}

#if !defined(LIBRESSL_VERSION_NUMBER)
TYPED_TEST(TokenTest, CreateTokenEd448) {

	auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(
		jwt::algorithm::ed448("", ed448_priv_key, "", ""));

	auto decoded = jwt::decode<TypeParam>(token);

	EXPECT_THROW(jwt::verify<TypeParam>()
					 .allow_algorithm(jwt::algorithm::ed448(ed448_pub_key_invalid, "", "", ""))
					 .verify(decoded),
				 jwt::error::signature_verification_exception);
	EXPECT_NO_THROW(
		jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::ed448(ed448_pub_key, "", "", "")).verify(decoded));
}
#endif // !LIBRESSL_VERSION_NUMBER
#endif // !JWT_OPENSSL_1_0_0 && !JWT_OPENSSL_1_1_0

TYPED_TEST(TokenTest, VerifyTokenWrongAlgorithm) {
	std::string token =
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.VA2i1ui1cnoD6I3wnji1WAVCf29EekysvevGrT2GXqK1dDMc8"
		"HAZCTQxa1Q8NppnpYV-hlqxh-X3Bb0JOePTGzjynpNZoJh2aHZD-GKpZt7OO1Zp8AFWPZ3p8Cahq8536fD8RiBES9jRsvChZvOqA7gMcFc4"
		"YD0iZhNIcI7a654u5yPYyTlf5kjR97prCf_OXWRn-bYY74zna4p_bP9oWCL4BkaoRcMxi-IR7kmVcCnvbYqyIrKloXP2qPO442RBGqU7Ov9"
		"sGQxiVqtRHKXZR9RbfvjrErY1KGiCp9M5i2bsUHadZEY44FE2jiOmx-uc2z5c05CCXqVSpfCjWbh9gQ";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::none{}).with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
}

TYPED_TEST(TokenTest, VerifyTokenNoneFail) {
	// None algorithm should not have a signature
	std::string token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpYXQiOjE1OTUyNjc1MTZ9.cmFuZG9tc2ln";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::none{});

	auto decoded_token = jwt::decode<TypeParam>(token);

	EXPECT_THROW(verify.verify(decoded_token), jwt::error::signature_verification_exception);
}

TYPED_TEST(TokenTest, VerifyTokenRS256FailNoKey) {
	EXPECT_THROW(
		[]() {
			auto verify =
				jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::rs256("", "", "", "")).with_issuer("auth0");
		}(),
		jwt::error::rsa_exception);
}

TYPED_TEST(TokenTest, VerifyTokenRS256) {
	std::string token =
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.VA2i1ui1cnoD6I3wnji1WAVCf29EekysvevGrT2GXqK1dDMc8"
		"HAZCTQxa1Q8NppnpYV-hlqxh-X3Bb0JOePTGzjynpNZoJh2aHZD-GKpZt7OO1Zp8AFWPZ3p8Cahq8536fD8RiBES9jRsvChZvOqA7gMcFc4"
		"YD0iZhNIcI7a654u5yPYyTlf5kjR97prCf_OXWRn-bYY74zna4p_bP9oWCL4BkaoRcMxi-IR7kmVcCnvbYqyIrKloXP2qPO442RBGqU7Ov9"
		"sGQxiVqtRHKXZR9RbfvjrErY1KGiCp9M5i2bsUHadZEY44FE2jiOmx-uc2z5c05CCXqVSpfCjWbh9gQ";

	auto verify = jwt::verify<TypeParam>()
					  .allow_algorithm(jwt::algorithm::rs256(rsa_pub_key, rsa_priv_key, "", ""))
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenEvpPkeyRS256) {
	std::string token =
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.VA2i1ui1cnoD6I3wnji1WAVCf29EekysvevGrT2GXqK1dDMc8"
		"HAZCTQxa1Q8NppnpYV-hlqxh-X3Bb0JOePTGzjynpNZoJh2aHZD-GKpZt7OO1Zp8AFWPZ3p8Cahq8536fD8RiBES9jRsvChZvOqA7gMcFc4"
		"YD0iZhNIcI7a654u5yPYyTlf5kjR97prCf_OXWRn-bYY74zna4p_bP9oWCL4BkaoRcMxi-IR7kmVcCnvbYqyIrKloXP2qPO442RBGqU7Ov9"
		"sGQxiVqtRHKXZR9RbfvjrErY1KGiCp9M5i2bsUHadZEY44FE2jiOmx-uc2z5c05CCXqVSpfCjWbh9gQ";

	auto verify = jwt::verify<TypeParam>()
					  .allow_algorithm(jwt::algorithm::rsa(jwt::helper::load_private_key_from_string(rsa_priv_key),
														   EVP_sha256, "RS256"))
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenRS256PublicOnly) {
	std::string token =
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.VA2i1ui1cnoD6I3wnji1WAVCf29EekysvevGrT2GXqK1dDMc8"
		"HAZCTQxa1Q8NppnpYV-hlqxh-X3Bb0JOePTGzjynpNZoJh2aHZD-GKpZt7OO1Zp8AFWPZ3p8Cahq8536fD8RiBES9jRsvChZvOqA7gMcFc4"
		"YD0iZhNIcI7a654u5yPYyTlf5kjR97prCf_OXWRn-bYY74zna4p_bP9oWCL4BkaoRcMxi-IR7kmVcCnvbYqyIrKloXP2qPO442RBGqU7Ov9"
		"sGQxiVqtRHKXZR9RbfvjrErY1KGiCp9M5i2bsUHadZEY44FE2jiOmx-uc2z5c05CCXqVSpfCjWbh9gQ";

	auto verify =
		jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::rs256(rsa_pub_key, "", "", "")).with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenEvpPkeyRS256PublicOnly) {
	std::string token =
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.VA2i1ui1cnoD6I3wnji1WAVCf29EekysvevGrT2GXqK1dDMc8"
		"HAZCTQxa1Q8NppnpYV-hlqxh-X3Bb0JOePTGzjynpNZoJh2aHZD-GKpZt7OO1Zp8AFWPZ3p8Cahq8536fD8RiBES9jRsvChZvOqA7gMcFc4"
		"YD0iZhNIcI7a654u5yPYyTlf5kjR97prCf_OXWRn-bYY74zna4p_bP9oWCL4BkaoRcMxi-IR7kmVcCnvbYqyIrKloXP2qPO442RBGqU7Ov9"
		"sGQxiVqtRHKXZR9RbfvjrErY1KGiCp9M5i2bsUHadZEY44FE2jiOmx-uc2z5c05CCXqVSpfCjWbh9gQ";

	auto verify = jwt::verify<TypeParam>()
					  .allow_algorithm(jwt::algorithm::rsa(jwt::helper::load_public_key_from_string(rsa_pub_key),
														   EVP_sha256, "RS256"))
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenRS256PublicOnlyEncrypted) {
	// openssl genrsa -aes256 -out private.pem 2048
	// openssl rsa -in private.pem -pubout -out public.pem
	const std::string rsa_passphrase = "helloworld";
	const std::string rsa_public = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtJWZsTVZxeeYWkSeVPvo
yQtHH6KjJ4HcV6bI7gQQlPjDKzleIuK2bjC9mEv9+ewxL5qoYHm6Q5iYA0tYkHx0
Aa8OkzvmWxIZirDKf6axAlL8xKdDK0HX9/oIam4OR5zw91NcHmEuMgBBu4ILkQfr
qCTETiXVYHHhcnwV6U10/enz8peDxEXo77oeI6CalRmH/g0Oj+S5yTQ3dsz3q8n8
tMHSxy1h3OQcQBZzgB/GiWheSyGyECX+/DqfZnIjb7zJRu8xoQI+qU0UXhntPiV+
ywHCPw0c+rmPgRkALmmUMyZ2sK72QpQjhOL59kAIg2Vz9PdKVLgP+ZW3nAzgrvvG
JwIDAQAB
-----END PUBLIC KEY-----)";

	std::string token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.HL2mq18xubKWG1j4GZI2DLBi-"
						"wajNyI9QotK31VjX1pQdfarHr9OsX5qiHydXfPBJSj-O4xIeH92LGslH1Z3rYiEwrq0dN6hr8nFfcBUYHu1nntYe_"
						"hVFXdx5oK8V427aKPUxlBq8MyOGLYFCXFKYWLinLTCihPHnEV5LFI2HGGtWm-"
						"S2OlNKawt24qnOhRtwE8QuckfOiiIjCtPH8798cOZzBrsqMdKTYhlFM28dTkejP_AgJUwD6QujSm2is0kAg1_"
						"SXxKTDSHVlg8irtG9ZQZXcuhaZCieAE1uIlJmKpEg4MUHVfvMsgy0N0p64NOiHa6bQsEb3NFn7UAe55jKQ";

	auto verify = jwt::verify<TypeParam>()
					  .allow_algorithm(jwt::algorithm::rs256(rsa_public, "", rsa_passphrase, ""))
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenRS256PrivateOnly) {
	std::string token =
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.VA2i1ui1cnoD6I3wnji1WAVCf29EekysvevGrT2GXqK1dDMc8"
		"HAZCTQxa1Q8NppnpYV-hlqxh-X3Bb0JOePTGzjynpNZoJh2aHZD-GKpZt7OO1Zp8AFWPZ3p8Cahq8536fD8RiBES9jRsvChZvOqA7gMcFc4"
		"YD0iZhNIcI7a654u5yPYyTlf5kjR97prCf_OXWRn-bYY74zna4p_bP9oWCL4BkaoRcMxi-IR7kmVcCnvbYqyIrKloXP2qPO442RBGqU7Ov9"
		"sGQxiVqtRHKXZR9RbfvjrErY1KGiCp9M5i2bsUHadZEY44FE2jiOmx-uc2z5c05CCXqVSpfCjWbh9gQ";

	auto verify =
		jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::rs256("", rsa_priv_key, "", "")).with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenRS256Fail) {
	std::string token =
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.VA2i1ui1cnoD6I3wnji1WAVCf29EekysvevGrT2GXqK1dDMc8"
		"HAZCTQxa1Q8NppnpYV-hlqxh-X3Bb0JOePTGzjynpNZoJh2aHZD-GKpZt7OO1Zp8AFWPZ3p8Cahq8536fD8RiBES9jRsvChZvOqA7gMcFc4"
		"YD0iZhNIcI7a654u5yPYyTlf5kjR97prCf_OXWRn-bYY74zna4p_bP9oWCL4BkaoRcMxi-IR7kmVcCnvbYqyIrKloXP2qPO442RBGqU7Ov9"
		"sGQxiVqtRHKXZR9RbfvjrErY1KGiCp9M5i2bsUHadZEY44FE2jiOmx-uc2z5c05CCXqVSpfCjWbh9gQ";

	auto verify = jwt::verify<TypeParam>()
					  .allow_algorithm(jwt::algorithm::rs256(rsa_pub_key_invalid, "", "", ""))
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	EXPECT_THROW(verify.verify(decoded_token), jwt::error::signature_verification_exception);
}

TYPED_TEST(TokenTest, VerifyTokenRS512) {
	std::string token =
		"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.GZhnjtsvBl2_KDSxg4JW6xnmNjr2mWhYSZ"
		"SSQyLKvI0TK86sJKchkt_HDy2IC5l5BGRhq_Xv9pHdA1umidQZG3a7gWvHsujqybCBgBraMTd1wJrCl4QxFg2RYHhHbRqb9BnPJgFD_vryd4"
		"GBhfGgejPBCBlGrQtqFGFdHHOjNHY";

	auto verify = jwt::verify<TypeParam>()
					  .allow_algorithm(jwt::algorithm::rs512(rsa512_pub_key, rsa512_priv_key, "", ""))
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenRS512PublicOnly) {
	std::string token =
		"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.GZhnjtsvBl2_KDSxg4JW6xnmNjr2mWhYSZ"
		"SSQyLKvI0TK86sJKchkt_HDy2IC5l5BGRhq_Xv9pHdA1umidQZG3a7gWvHsujqybCBgBraMTd1wJrCl4QxFg2RYHhHbRqb9BnPJgFD_vryd4"
		"GBhfGgejPBCBlGrQtqFGFdHHOjNHY";

	auto verify = jwt::verify<TypeParam>()
					  .allow_algorithm(jwt::algorithm::rs512(rsa512_pub_key, "", "", ""))
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenRS512PrivateOnly) {
	std::string token =
		"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.GZhnjtsvBl2_KDSxg4JW6xnmNjr2mWhYSZ"
		"SSQyLKvI0TK86sJKchkt_HDy2IC5l5BGRhq_Xv9pHdA1umidQZG3a7gWvHsujqybCBgBraMTd1wJrCl4QxFg2RYHhHbRqb9BnPJgFD_vryd4"
		"GBhfGgejPBCBlGrQtqFGFdHHOjNHY";

	auto verify = jwt::verify<TypeParam>()
					  .allow_algorithm(jwt::algorithm::rs512("", rsa512_priv_key, "", ""))
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenRS512Fail) {
	std::string token =
		"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.GZhnjtsvBl2_KDSxg4JW6xnmNjr2mWhYSZ"
		"SSQyLKvI0TK86sJKchkt_HDy2IC5l5BGRhq_Xv9pHdA1umidQZG3a7gWvHsujqybCBgBraMTd1wJrCl4QxFg2RYHhHbRqb9BnPJgFD_vryd4"
		"GBhfGgejPBCBlGrQtqFGFdHHOjNHY";

	auto verify = jwt::verify<TypeParam>()
					  .allow_algorithm(jwt::algorithm::rs512(rsa_pub_key_invalid, "", "", ""))
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	EXPECT_THROW(verify.verify(decoded_token), jwt::error::signature_verification_exception);
}

TYPED_TEST(TokenTest, VerifyTokenHS256) {
	std::string token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::hs256{"secret"}).with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);
	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenHS256Fail) {
	std::string token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::hs256{"wrongsecret"}).with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);
	EXPECT_THROW(verify.verify(decoded_token), jwt::error::signature_verification_exception);
}

TYPED_TEST(TokenTest, VerifyTokenHS256FailSignatureLength) {
	std::string token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkA";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::hs256{"secret"}).with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);
	EXPECT_THROW(verify.verify(decoded_token), jwt::error::signature_verification_exception);
}

TYPED_TEST(TokenTest, VerifyFail) {
	{
		auto token = jwt::create<TypeParam>()
						 .set_issuer("auth0")
						 .set_type("JWS")
						 .set_audience("random")
						 .set_payload_claim("typetest", typename TypeParam::value_type(10.0))
						 .sign(jwt::algorithm::none{});

		auto decoded_token = jwt::decode<TypeParam>(token);

		{
			auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::none{}).with_issuer("auth");
			EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
		}
		{
			auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::none{}).with_type("JWT");
			EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
		}
		{
			auto verify = jwt::verify<TypeParam>()
							  .allow_algorithm(jwt::algorithm::none{})
							  .with_issuer("auth0")
							  .with_audience(std::set<std::string>{"test"});
			EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
		}
		{
			auto verify = jwt::verify<TypeParam>()
							  .allow_algorithm(jwt::algorithm::none{})
							  .with_issuer("auth0")
							  .with_audience("test");
			EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
		}
		{
			auto verify = jwt::verify<TypeParam>()
							  .allow_algorithm(jwt::algorithm::none{})
							  .with_issuer("auth0")
							  .with_subject("test");
			EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
		}
		{
			auto verify = jwt::verify<TypeParam>()
							  .allow_algorithm(jwt::algorithm::none{})
							  .with_issuer("auth0")
							  .with_claim("myclaim", jwt::basic_claim<TypeParam>(std::string("test")));
			EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
		}
		{
			auto verify =
				jwt::verify<TypeParam>()
					.allow_algorithm(jwt::algorithm::none{})
					.with_issuer("auth0")
					.with_claim("typetest", jwt::basic_claim<TypeParam>(typename TypeParam::value_type(true)));
			EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
		}
		{
			jwt::basic_claim<TypeParam> object;
			std::istringstream iss{R"({ "test": null })"};
			iss >> object;
			EXPECT_EQ(object.get_type(), jwt::json::type::object);

			auto verify = jwt::verify<TypeParam>()
							  .allow_algorithm(jwt::algorithm::none{})
							  .with_issuer("auth0")
							  .with_claim("myclaim", object);
			EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
		}
	}
	{
		auto token = jwt::create<TypeParam>().set_issuer("auth0").set_type("JWS").sign(jwt::algorithm::none{});

		auto decoded_token = jwt::decode<TypeParam>(token);

		{
			auto verify = jwt::verify<TypeParam>()
							  .allow_algorithm(jwt::algorithm::none{})
							  .with_issuer("auth0")
							  .with_audience("test");
			EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
		}
	}
}

TYPED_TEST(TokenTest, VerifyTokenES256FailNoKey) {
	EXPECT_THROW(
		[]() {
			auto verify =
				jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::es256("", "", "", "")).with_issuer("auth0");
		}(),
		jwt::error::ecdsa_exception);
}

TYPED_TEST(TokenTest, VerifyTokenEvpPkeyES256FailNoKey) {
	EXPECT_THROW(
		[]() {
			auto verify = jwt::verify<TypeParam>()
							  .allow_algorithm(
								  jwt::algorithm::ecdsa(jwt::helper::evp_pkey_handle{nullptr}, EVP_sha256, "ES256", 64))
							  .with_issuer("auth0");
		}(),
		jwt::error::ecdsa_exception);
}

TYPED_TEST(TokenTest, VerifyTokenES256) {
	const std::string token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_"
							  "4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::es256(ecdsa256_pub_key, "", "", ""));
	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenEvpPkeyES256) {
	const std::string token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_"
							  "4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(
		jwt::algorithm::ecdsa(jwt::helper::load_public_ec_key_from_string(ecdsa256_pub_key), EVP_sha256, "ES256", 64));
	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenES256Fail) {
	const std::string token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_"
							  "4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::es256(ecdsa256_pub_key_invalid, "", "", ""));
	auto decoded_token = jwt::decode<TypeParam>(token);

	EXPECT_THROW(verify.verify(decoded_token), jwt::error::signature_verification_exception);
}

TYPED_TEST(TokenTest, VerifyTokenES384) {
	const std::string token =
		"eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.nTUwWanmj_K1VZM5it1ES-1FbnmRDL-lH3V_Fem-"
		"AhMur9Q61yZfKIydrpdavkm_SMxEsUGPVoqkpoEsjFjrtzMDs5s9yaFYD_ydiy1dsn9VbcI55voA3XwEcWFiPHri";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::es384(ecdsa384_pub_key, "", "", ""));
	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenES384Fail) {
	const std::string token =
		"eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.nTUwWanmj_K1VZM5it1ES-1FbnmRDL-lH3V_Fem-"
		"AhMur9Q61yZfKIydrpdavkm_SMxEsUGPVoqkpoEsjFjrtzMDs5s9yaFYD_ydiy1dsn9VbcI55voA3XwEcWFiPHri";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::es384(ecdsa384_pub_key_invalid, "", "", ""));
	auto decoded_token = jwt::decode<TypeParam>(token);

	EXPECT_THROW(verify.verify(decoded_token), jwt::error::signature_verification_exception);
}

TYPED_TEST(TokenTest, VerifyTokenES521) {
	const std::string token =
		"eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.ASF5hh9_Jyujzm3GRBttoth-3I6lCcwqun9Tt7Ekz9_23BN6-"
		"BFgwKidECWCNc4VINEqFEFdApC2y3YRdkpKX2etAWI7yYudAlxJ7Z17m6GwAoLOGaeNonsaKOe1UnC5W86eoXrCoPRgzsFTpKIb8NiolcYWjIY"
		"-r8gQd7BZ7whaj9Ft";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::es512(ecdsa521_pub_key, "", "", ""));
	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenES521Fail) {
	const std::string token =
		"eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.ASF5hh9_Jyujzm3GRBttoth-3I6lCcwqun9Tt7Ekz9_23BN6-"
		"BFgwKidECWCNc4VINEqFEFdApC2y3YRdkpKX2etAWI7yYudAlxJ7Z17m6GwAoLOGaeNonsaKOe1UnC5W86eoXrCoPRgzsFTpKIb8NiolcYWjIY"
		"-r8gQd7BZ7whaj9Ft";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::es512(ecdsa521_pub_key_invalid, "", "", ""));
	auto decoded_token = jwt::decode<TypeParam>(token);

	EXPECT_THROW(verify.verify(decoded_token), jwt::error::signature_verification_exception);
}

TYPED_TEST(TokenTest, VerifyTokenPS256) {
	std::string token =
		"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.CJ4XjVWdbV6vXGZkD4GdJbtYc80SN9cmPOqRhZBRzOyDRqTFE"
		"4MsbdKyQuhAWcvuMOjn-24qOTjVMR_P_uTC1uG6WPLcucxZyLnbb56zbKnEklW2SX0mQnCGewr-93a_vDaFT6Cp45MsF_OwFPRCMaS5CJg-"
		"N5KY67UrVSr3s9nkuK9ZTQkyODHfyEUh9F_FhRCATGrb5G7_qHqBYvTvaPUXqzhhpCjN855Tocg7A24Hl0yMwM-XdasucW5xNdKjG_YCkis"
		"HX7ax--JiF5GNYCO61eLFteO4THUg-3Z0r4OlGqlppyWo5X5tjcxOZCvBh7WDWfkxA48KFZPRv0nlKA";

	auto verify = jwt::verify<TypeParam>()
					  .allow_algorithm(jwt::algorithm::ps256(rsa_pub_key, rsa_priv_key, "", ""))
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenPS256PublicOnly) {
	std::string token =
		"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.CJ4XjVWdbV6vXGZkD4GdJbtYc80SN9cmPOqRhZBRzOyDRqTFE"
		"4MsbdKyQuhAWcvuMOjn-24qOTjVMR_P_uTC1uG6WPLcucxZyLnbb56zbKnEklW2SX0mQnCGewr-93a_vDaFT6Cp45MsF_OwFPRCMaS5CJg-"
		"N5KY67UrVSr3s9nkuK9ZTQkyODHfyEUh9F_FhRCATGrb5G7_qHqBYvTvaPUXqzhhpCjN855Tocg7A24Hl0yMwM-XdasucW5xNdKjG_YCkis"
		"HX7ax--JiF5GNYCO61eLFteO4THUg-3Z0r4OlGqlppyWo5X5tjcxOZCvBh7WDWfkxA48KFZPRv0nlKA";

	auto verify =
		jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::ps256(rsa_pub_key, "", "", "")).with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenPS256Fail) {
	std::string token =
		"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.CJ4XjVWdbV6vXGZkD4GdJbtYc80SN9cmPOqRhZBRzOyDRqTFE"
		"4MsbdKyQuhAWcvuMOjn-24qOTjVMR_P_uTC1uG6WPLcucxZyLnbb56zbKnEklW2SX0mQnCGewr-93a_vDaFT6Cp45MsF_OwFPRCMaS5CJg-"
		"N5KY67UrVSr3s9nkuK9ZTQkyODHfyEUh9F_FhRCATGrb5G7_qHqBYvTvaPUXqzhhpCjN855Tocg7A24Hl0yMwM-XdasucW5xNdKjG_YCkis"
		"HX7ax--JiF5GNYCO61eLFteO4THUg-3Z0r4OlGqlppyWo5X5tjcxOZCvBh7WDWfkxA48KFZPRv0nlKA";

	auto verify = jwt::verify<TypeParam>()
					  .allow_algorithm(jwt::algorithm::ps256(rsa_pub_key_invalid, "", "", ""))
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<TypeParam>(token);

	EXPECT_THROW(verify.verify(decoded_token), jwt::error::signature_verification_exception);
}

TYPED_TEST(TokenTest, VerifyTokenPS256FailNoKey) {
	EXPECT_THROW(
		[]() {
			auto verify =
				jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::ps256("", "", "", "")).with_issuer("auth0");
		}(),
		jwt::error::rsa_exception);
}

#if !defined(JWT_OPENSSL_1_0_0) && !defined(JWT_OPENSSL_1_1_0)
TYPED_TEST(TokenTest, VerifyTokenEd25519) {
	const std::string token =
		"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.OujgVcO8xQx5xLcAYWENCRU1SCGH5HcX4MX4o6wU3M4"
		"DOnKiNmc0O2AnvQlzr-9cgI4QGQzeC6gz_fgLoesADg";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::ed25519(ed25519_pub_key, "", "", ""));
	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenEd25519Fail) {
	const std::string token =
		"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.OujgVcO8xQx5xLcAYWENCRU1SCGH5HcX4MX4o6wU3M4"
		"DOnKiNmc0O2AnvQlzr-9cgI4QGQzeC6gz_fgLoesADg";

	auto verify =
		jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::ed25519(ed25519_pub_key_invalid, "", "", ""));
	auto decoded_token = jwt::decode<TypeParam>(token);

	EXPECT_THROW(verify.verify(decoded_token), jwt::error::signature_verification_exception);
}

#if !defined(LIBRESSL_VERSION_NUMBER)
TYPED_TEST(TokenTest, VerifyTokenEd448) {
	const std::string token =
		"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.Aldes9jrXZXxfNjuovqmIZ3r2WF4yVXVr2Q8B8SkAmv"
		"Bsw_3MHs8HtgKeXbqKFYWpHOCtmZJcH-AWMvoY6FCNdQqbESGTkv58O6tFbXDD_nLejWNAOuvcO2LPMySmkVNQUopmQf_HO62Mug1ngepUDE"
		"A";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::ed448(ed448_pub_key, "", "", ""));
	auto decoded_token = jwt::decode<TypeParam>(token);

	verify.verify(decoded_token);
}

TYPED_TEST(TokenTest, VerifyTokenEd448Fail) {
	const std::string token =
		"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.Aldes9jrXZXxfNjuovqmIZ3r2WF4yVXVr2Q8B8SkAmv"
		"Bsw_3MHs8HtgKeXbqKFYWpHOCtmZJcH-AWMvoY6FCNdQqbESGTkv58O6tFbXDD_nLejWNAOuvcO2LPMySmkVNQUopmQf_HO62Mug1ngepUDE"
		"A";

	auto verify = jwt::verify<TypeParam>().allow_algorithm(jwt::algorithm::ed448(ed448_pub_key_invalid, "", "", ""));
	auto decoded_token = jwt::decode<TypeParam>(token);

	EXPECT_THROW(verify.verify(decoded_token), jwt::error::signature_verification_exception);
}
#endif // !LIBRESSL_VERSION_NUMBER
#endif // !JWT_OPENSSL_1_0_0 && !JWT_OPENSSL_1_1_0

struct test_clock {
	jwt::date n;
	jwt::date now() const { return n; }
};

TYPED_TEST(TokenTest, VerifyTokenExpireFail) {
	auto token = jwt::create<TypeParam>()
					 .set_expires_at(std::chrono::system_clock::from_time_t(100))
					 .sign(jwt::algorithm::none{});
	auto decoded_token = jwt::decode<TypeParam>(token);

	auto verify = jwt::verify<test_clock, TypeParam>({std::chrono::system_clock::from_time_t(110)})
					  .allow_algorithm(jwt::algorithm::none{});
	EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
	std::error_code ec;
	EXPECT_NO_THROW(verify.verify(decoded_token, ec));
	EXPECT_TRUE(!(!ec));
	EXPECT_EQ(ec.category(), jwt::error::token_verification_error_category());
	EXPECT_EQ(ec.value(), static_cast<int>(jwt::error::token_verification_error::token_expired));
}

TYPED_TEST(TokenTest, VerifyTokenExpire) {
	auto token = jwt::create<TypeParam>()
					 .set_expires_at(std::chrono::system_clock::from_time_t(100))
					 .sign(jwt::algorithm::none{});
	auto decoded_token = jwt::decode<TypeParam>(token);

	auto verify = jwt::verify<test_clock, TypeParam>({std::chrono::system_clock::from_time_t(90)})
					  .allow_algorithm(jwt::algorithm::none{});
	EXPECT_NO_THROW(verify.verify(decoded_token));
	std::error_code ec;
	EXPECT_NO_THROW(verify.verify(decoded_token, ec));
	EXPECT_FALSE(!(!ec));
	EXPECT_EQ(ec.value(), 0);
}

TYPED_TEST(TokenTest, VerifyTokenNBFFail) {
	auto token = jwt::create<TypeParam>()
					 .set_not_before(std::chrono::system_clock::from_time_t(100))
					 .sign(jwt::algorithm::none{});
	auto decoded_token = jwt::decode<TypeParam>(token);

	auto verify = jwt::verify<test_clock, TypeParam>({std::chrono::system_clock::from_time_t(90)})
					  .allow_algorithm(jwt::algorithm::none{});
	EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
	std::error_code ec;
	EXPECT_NO_THROW(verify.verify(decoded_token, ec));
	EXPECT_TRUE(!(!ec));
	EXPECT_EQ(ec.category(), jwt::error::token_verification_error_category());
	EXPECT_EQ(ec.value(), static_cast<int>(jwt::error::token_verification_error::token_expired));
}

TYPED_TEST(TokenTest, VerifyTokenNBF) {
	auto token = jwt::create<TypeParam>()
					 .set_not_before(std::chrono::system_clock::from_time_t(100))
					 .sign(jwt::algorithm::none{});
	auto decoded_token = jwt::decode<TypeParam>(token);

	auto verify = jwt::verify<test_clock, TypeParam>({std::chrono::system_clock::from_time_t(110)})
					  .allow_algorithm(jwt::algorithm::none{});
	EXPECT_NO_THROW(verify.verify(decoded_token));
	std::error_code ec;
	EXPECT_NO_THROW(verify.verify(decoded_token, ec));
	EXPECT_FALSE(!(!ec));
	EXPECT_EQ(ec.value(), 0);
}

TYPED_TEST(TokenTest, VerifyTokenIATFail) {
	auto token = jwt::create<TypeParam>()
					 .set_issued_at(std::chrono::system_clock::from_time_t(100))
					 .sign(jwt::algorithm::none{});
	auto decoded_token = jwt::decode<TypeParam>(token);

	auto verify = jwt::verify<test_clock, TypeParam>({std::chrono::system_clock::from_time_t(90)})
					  .allow_algorithm(jwt::algorithm::none{});
	EXPECT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);
	std::error_code ec;
	EXPECT_NO_THROW(verify.verify(decoded_token, ec));
	EXPECT_TRUE(!(!ec));
	EXPECT_EQ(ec.category(), jwt::error::token_verification_error_category());
	EXPECT_EQ(ec.value(), static_cast<int>(jwt::error::token_verification_error::token_expired));
}

TYPED_TEST(TokenTest, VerifyTokenIAT) {
	auto token = jwt::create<TypeParam>()
					 .set_issued_at(std::chrono::system_clock::from_time_t(100))
					 .sign(jwt::algorithm::none{});
	auto decoded_token = jwt::decode<TypeParam>(token);

	auto verify = jwt::verify<test_clock, TypeParam>({std::chrono::system_clock::from_time_t(110)})
					  .allow_algorithm(jwt::algorithm::none{});
	EXPECT_NO_THROW(verify.verify(decoded_token));
	std::error_code ec;
	EXPECT_NO_THROW(verify.verify(decoded_token, ec));
	EXPECT_FALSE(!(!ec));
	EXPECT_EQ(ec.value(), 0);
}

TYPED_TEST(TokenTest, VerifyTokenType) {
	ASSERT_NO_THROW(jwt::create<TypeParam>().set_type("JWS").sign(jwt::algorithm::none{}));
	auto token = jwt::create<TypeParam>().set_type("JWS").sign(jwt::algorithm::none{});
	ASSERT_NO_THROW(jwt::decode<TypeParam>(token));
	auto decoded_token = jwt::decode<TypeParam>(token);

	ASSERT_NO_THROW(
		jwt::verify<TypeParam>().with_type("jws").allow_algorithm(jwt::algorithm::none{}).verify(decoded_token));
	auto verify = jwt::verify<TypeParam>().with_type("jws").allow_algorithm(jwt::algorithm::none{});
	EXPECT_NO_THROW(verify.verify(decoded_token));
	std::error_code ec;
	EXPECT_NO_THROW(verify.verify(decoded_token, ec));
	EXPECT_FALSE(!(!ec));
	EXPECT_EQ(ec.value(), 0);
}

TYPED_TEST(TokenTest, GetClaimThrows) {
	const std::string token = "eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJpc3MiOiJhdXRoMCJ9.";
	auto decoded_token = jwt::decode<TypeParam>(token);

	EXPECT_THROW(decoded_token.get_header_claim("test"), jwt::error::claim_not_present_exception);
	EXPECT_THROW(decoded_token.get_payload_claim("test"), jwt::error::claim_not_present_exception);
}

TEST(TokenTest, ThrowInvalidKeyLength) {
	// We should throw if passed the wrong size
	EXPECT_THROW(jwt::algorithm::es256(ecdsa384_pub_key, ""), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es256("", ecdsa384_priv_key), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es256(ecdsa384_pub_key, ecdsa384_priv_key), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es256(ecdsa521_pub_key, ""), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es256("", ecdsa521_priv_key), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es256(ecdsa521_pub_key, ecdsa521_priv_key), jwt::error::ecdsa_exception);

	// But also if only one cert has the wrong size
	EXPECT_THROW(jwt::algorithm::es256(ecdsa256_pub_key, ecdsa384_priv_key), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es256(ecdsa256_pub_key, ecdsa521_priv_key), jwt::error::ecdsa_exception);

	EXPECT_THROW(jwt::algorithm::es384(ecdsa256_pub_key, ""), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es384("", ecdsa256_priv_key), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es384(ecdsa256_pub_key, ecdsa256_priv_key), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es384(ecdsa521_pub_key, ""), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es384("", ecdsa521_priv_key), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es384(ecdsa521_pub_key, ecdsa521_priv_key), jwt::error::ecdsa_exception);

	EXPECT_THROW(jwt::algorithm::es384(ecdsa384_pub_key, ecdsa256_priv_key), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es384(ecdsa384_pub_key, ecdsa521_priv_key), jwt::error::ecdsa_exception);

	EXPECT_THROW(jwt::algorithm::es512(ecdsa256_pub_key, ""), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es512("", ecdsa256_priv_key), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es512(ecdsa256_pub_key, ecdsa256_priv_key), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es512(ecdsa384_pub_key, ""), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es512("", ecdsa384_priv_key), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es512(ecdsa384_pub_key, ecdsa384_priv_key), jwt::error::ecdsa_exception);

	EXPECT_THROW(jwt::algorithm::es512(ecdsa521_pub_key, ecdsa256_priv_key), jwt::error::ecdsa_exception);
	EXPECT_THROW(jwt::algorithm::es512(ecdsa521_pub_key, ecdsa384_priv_key), jwt::error::ecdsa_exception);

	// Make sure we do not throw if the correct params are passed
	EXPECT_NO_THROW(jwt::algorithm::es256(ecdsa256_pub_key, ecdsa256_priv_key));
	EXPECT_NO_THROW(jwt::algorithm::es384(ecdsa384_pub_key, ecdsa384_priv_key));
	EXPECT_NO_THROW(jwt::algorithm::es512(ecdsa521_pub_key, ecdsa521_priv_key));
}

TYPED_TEST(TokenTest, MoveDecodedToken) {
	const std::string token0 = "eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJpc3MiOiJhdXRoMCJ9.";
	const std::string token1 =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
	auto decoded_token0 = jwt::decode<TypeParam>(token0);
	auto decoded_token1 = jwt::decode<TypeParam>(token1);
	decoded_token0 = std::move(decoded_token1);
	EXPECT_EQ(token1, decoded_token0.get_token());

	EXPECT_TRUE(decoded_token0.has_algorithm());
	EXPECT_TRUE(decoded_token0.has_type());
	EXPECT_FALSE(decoded_token0.has_content_type());
	EXPECT_FALSE(decoded_token0.has_key_id());
	EXPECT_TRUE(decoded_token0.has_issuer());
	EXPECT_FALSE(decoded_token0.has_subject());
	EXPECT_FALSE(decoded_token0.has_audience());
	EXPECT_FALSE(decoded_token0.has_expires_at());
	EXPECT_FALSE(decoded_token0.has_not_before());
	EXPECT_FALSE(decoded_token0.has_issued_at());
	EXPECT_FALSE(decoded_token0.has_id());

	EXPECT_EQ("HS256", decoded_token0.get_algorithm());
	EXPECT_EQ("JWS", decoded_token0.get_type());
	EXPECT_EQ("auth0", decoded_token0.get_issuer());
}
