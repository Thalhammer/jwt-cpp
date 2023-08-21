#include "jwt-cpp/jwt.h"
#include <gtest/gtest.h>

std::string pubkey_expected =
	R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwoB3iVm4RW+6StkR+nut
x1fQevu2+t0Fu6KBcbvhfyHSXy7w0nJOdTT4jWLjStpRkNQBPZwMwHH35i+21gdn
JtDe/xfO8IX9McFmyodlBUcqX8CruIzDv9AXf2OjXPBG+4aq+03XKl5/muATl32+
+301Vw1dXoGYNeoWQqLTsHT3WS3tOOf+ehuzNuZ+rj+ephaD3lMBToEArrtC9R91
KTTN6YSAOK48NxTA8CfOMFK5itxfIqB5+E9OSQTidXyqLyoeA+xxTKMqYfxvypEe
k1oueAhY9u67NCBdmuavxtfyvwp7+o6Sd+NsewxAhmRKFexw13KOYzDhC+9aMJcu
JQIDAQAB
-----END PUBLIC KEY-----
)";

std::string modulus =
	R"(AMKAd4lZuEVvukrZEfp7rcdX0Hr7tvrdBbuigXG74X8h0l8u8NJyTnU0-I1i40raUZDUAT2cDMBx9-YvttYHZybQ3v8XzvCF_THBZsqHZQVHKl_Aq7iMw7_QF39jo1zwRvuGqvtN1ypef5rgE5d9vvt9NVcNXV6BmDXqFkKi07B091kt7Tjn_nobszbmfq4_nqYWg95TAU6BAK67QvUfdSk0zemEgDiuPDcUwPAnzjBSuYrcXyKgefhPTkkE4nV8qi8qHgPscUyjKmH8b8qRHpNaLngIWPbuuzQgXZrmr8bX8r8Ke_qOknfjbHsMQIZkShXscNdyjmMw4QvvWjCXLiU)";
std::string exponent = R"(AQAB)";

TEST(PubKeyTest, RSAFromComponents) {
	const auto pubkey = jwt::helper::create_public_key_from_rsa_components(modulus, exponent);

	ASSERT_EQ(pubkey, pubkey_expected);
}
