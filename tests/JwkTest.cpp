#include "jwt-cpp/jwt.h"
#include <gtest/gtest.h>

/*
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2KvGTTxorqX2rvLOASWcBOqevGo5eIFFUVSlQIWe8x/a19mT
XbYz6l3FYZ0s2W172nBpzJggi6PLK3397JsjjrzXb1pgXCVjIjM4hs5HDNtoWmC3
/+O1jWknfrUHS95KWJkKg77B3ShGO1n8drfXCL4lWdo8F3UtVjHgfYEHI1xLSv3n
v8QfGpOnWh4MAdmXhcankZQNuip6pwKlF+3y2WfukHN3rAmMx1MyID77srgPW7A3
f0FTiGUz5gfUdp+5MMSQbhSZTM9fXu0buU4cmL35W9GoExjfjXlixpl70HWdyeLY
SNyZKaw/Tqjwq769xf5sJZBe5UP6hL/dbLYhvQIDAQABAoIBACtorsAGnEpxQazn
RFKCgHGTt92zwnPcIlEbDkiQ/Llk5mlcU+PwfxIzWzolTTj6cFfhMbElwU94r1m1
Ukw3ALa2KstKZgfQDb5qWKbZaO6wfoWs3vBLZLJCIQGHr0CJ9octkie27gwq53c4
nhYC2vgLcFxCFsv0U/Ly5zD9yrpQgv3DElKbc2zal/Z+kBt9MAN+2S4Fh2LaEUUl
8QXjxdxbe3PHvX4nO5TWM3ztcfANzPDAWFJDeOgciUK6wEqTxkmgjh4uMaDG5X3V
5xQRLBnFVXYzdwAVjzJVk9RvIDSQnEgYyHLBX6d190F85G8zQMVEwvs2VD1qJO+0
BppwloECgYEA7T2xC7xGtxn/Tg9lhItZzE371mTffZDNbhL2YDQt6jBHq40cmmBi
MzAYhV0Z7nky3bVHQUdaDLnJYIsqIrqqxGUZjcnkajhsSd1YGBwTHAv1njr+BX9a
zY15u/pNb+OYY6naFHuTmen/NKSha+s+kHmQGCEKzErhfZ4yXhrPETECgYEA6c2y
3iojU/P73RyUcoWQnDdOuQ8YNMAqoGwh/FzkG9futAiyhB3mGPmn7nw79rIO02Og
Rjk7t1qSSL5DX1oAP3Fq/G1HE9epgM4j82Sa9vpUZpoLBefD2wUDjD4QmzKcFuYv
M/Wl6dMLURllL24IdsEctR1p76Y7Spm251k/1k0CgYBpMxMAFjPxW6jXb4JfvP9L
1kTXNBHad0xxBB2WWW0GzPPrAX7ugdDpy+kDsl4eXkYNBCadrssim3vNwMglcErr
Hb2wHxeXdn+mXW2D+2cJ58+5o4Ui4O9d+N9DWOHfvLfFcfsPXCD+fkG5kUs3NLCg
lhcsa/KC1q2Y636ANjkd8QKBgQCP882AilNMGnnljvY7eM8rz8XRnWCbAgJ82Xcn
aY4tMotPH9fCDqKgl/50kNterg0AzGNfOVfyMXrF/ReAOurSJSPpHeNYbT15B/MM
pdHf5QtYTNoinatyS6j+jSwuUj/WvY0sob+wsvdRzKAHTuk5LPde8ChMnH3/FZuO
3921NQKBgQCSJf1kVFuxoWtdxqII0QJv6jSMaftK5xNkWCiLpmdttDpOdLRnMrYb
XXkgbME3NheApU1oXIehLyXG46DmFXCNKME98NuJ5ENvLVkOsGyPhZDtQtQT099J
z8gE19JF3RSmwvcaNpsLRg24BId/GmrZKgz9TEQMm+5wt93XcKtj6w==
-----END RSA PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2KvGTTxorqX2rvLOASWc
BOqevGo5eIFFUVSlQIWe8x/a19mTXbYz6l3FYZ0s2W172nBpzJggi6PLK3397Jsj
jrzXb1pgXCVjIjM4hs5HDNtoWmC3/+O1jWknfrUHS95KWJkKg77B3ShGO1n8drfX
CL4lWdo8F3UtVjHgfYEHI1xLSv3nv8QfGpOnWh4MAdmXhcankZQNuip6pwKlF+3y
2WfukHN3rAmMx1MyID77srgPW7A3f0FTiGUz5gfUdp+5MMSQbhSZTM9fXu0buU4c
mL35W9GoExjfjXlixpl70HWdyeLYSNyZKaw/Tqjwq769xf5sJZBe5UP6hL/dbLYh
vQIDAQAB
-----END PUBLIC KEY-----
*/

TEST(JwkTest, RsaKey) {
	std::string token =
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.IzM0dgbhU1CsRbjmwyPHXkc8LagqFtsZD6p1ls_"
		"WBugkEKNfFmZmhOM1YYiFg59xId_KtzNdp4puzGIafut15U06DL2ZGH_H4xE7ONy6WLA_i5z5H8gPxD3ui2W4nHEEf-mvqKSn-"
		"bU8YPUydrwK3dVRfP5JA9XJT0KhssSCnty99y853xvuTh0484atxMjIk2LvnIWlYXFgoggC8TMY-4AtAJDfF8aVJXT0m-"
		"90oNevJbxMsuf5XFKo30TWxlnRw-y-QsYr9pxj2sA0BdwqRKVRRg5KF-"
		"p6rIEbAv3A6UuzLORvtixp5AASS7nrBlZ1BB8q2hYFCPtOv6UETIIkaQ";
	std::string public_key = R"({
		"kty": "RSA",
		"n": "2KvGTTxorqX2rvLOASWcBOqevGo5eIFFUVSlQIWe8x_a19mTXbYz6l3FYZ0s2W172nBpzJggi6PLK3397JsjjrzXb1pgXCVjIjM4hs5HDNtoWmC3_-O1jWknfrUHS95KWJkKg77B3ShGO1n8drfXCL4lWdo8F3UtVjHgfYEHI1xLSv3nv8QfGpOnWh4MAdmXhcankZQNuip6pwKlF-3y2WfukHN3rAmMx1MyID77srgPW7A3f0FTiGUz5gfUdp-5MMSQbhSZTM9fXu0buU4cmL35W9GoExjfjXlixpl70HWdyeLYSNyZKaw_Tqjwq769xf5sJZBe5UP6hL_dbLYhvQ",
		"e": "AQAB"
	})";

	auto jwk = jwt::parse_jwk(public_key);
	ASSERT_EQ("RSA", jwk.get_key_type());
	auto verifier = jwt::verify();
	verifier.allow_key(jwk);
	auto decoded_token = jwt::decode(token);
	ASSERT_NO_THROW(verifier.verify(decoded_token));
}

TEST(JwkTest, HmacKey) {
	std::string token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
	std::string secret_key = R"({
		"kty": "oct",
		"k": "c2VjcmV0"
	})";

	auto jwk = jwt::parse_jwk(secret_key);
	ASSERT_EQ("oct", jwk.get_key_type());
	auto verifier = jwt::verify();
	verifier.allow_key(jwk);
	auto decoded_token = jwt::decode(token);
	ASSERT_NO_THROW(verifier.verify(decoded_token));
}
