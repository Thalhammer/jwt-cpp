#include "jwt-cpp/base.h"
#include <gtest/gtest.h>

TEST(BaseTest, Base64Decode) {
	ASSERT_EQ("1", jwt::base::decode<jwt::alphabet::base64>("MQ=="));
	ASSERT_EQ("12", jwt::base::decode<jwt::alphabet::base64>("MTI="));
	ASSERT_EQ("123", jwt::base::decode<jwt::alphabet::base64>("MTIz"));
	ASSERT_EQ("1234", jwt::base::decode<jwt::alphabet::base64>("MTIzNA=="));
}

TEST(BaseTest, Base64DecodeURL) {
	ASSERT_EQ("1", jwt::base::decode<jwt::alphabet::base64url>("MQ%3d%3d"));
	ASSERT_EQ("12", jwt::base::decode<jwt::alphabet::base64url>("MTI%3d"));
	ASSERT_EQ("123", jwt::base::decode<jwt::alphabet::base64url>("MTIz"));
	ASSERT_EQ("1234", jwt::base::decode<jwt::alphabet::base64url>("MTIzNA%3d%3d"));
}

TEST(BaseTest, Base64Encode) {
	ASSERT_EQ("MQ==", jwt::base::encode<jwt::alphabet::base64>("1"));
	ASSERT_EQ("MTI=", jwt::base::encode<jwt::alphabet::base64>("12"));
	ASSERT_EQ("MTIz", jwt::base::encode<jwt::alphabet::base64>("123"));
	ASSERT_EQ("MTIzNA==", jwt::base::encode<jwt::alphabet::base64>("1234"));
}

TEST(BaseTest, Base64EncodeURL) {
	ASSERT_EQ("MQ%3d%3d", jwt::base::encode<jwt::alphabet::base64url>("1"));
	ASSERT_EQ("MTI%3d", jwt::base::encode<jwt::alphabet::base64url>("12"));
	ASSERT_EQ("MTIz", jwt::base::encode<jwt::alphabet::base64url>("123"));
	ASSERT_EQ("MTIzNA%3d%3d", jwt::base::encode<jwt::alphabet::base64url>("1234"));
}

TEST(BaseTest, Base64Pad) {
	ASSERT_EQ("MQ==", jwt::base::pad<jwt::alphabet::base64>("MQ"));
	ASSERT_EQ("MTI=", jwt::base::pad<jwt::alphabet::base64>("MTI"));
	ASSERT_EQ("MTIz", jwt::base::pad<jwt::alphabet::base64>("MTIz"));
	ASSERT_EQ("MTIzNA==", jwt::base::pad<jwt::alphabet::base64>("MTIzNA"));
}

TEST(BaseTest, Base64PadURL) {
	ASSERT_EQ("MQ%3d%3d", jwt::base::pad<jwt::alphabet::base64url>("MQ"));
	ASSERT_EQ("MTI%3d", jwt::base::pad<jwt::alphabet::base64url>("MTI"));
	ASSERT_EQ("MTIz", jwt::base::pad<jwt::alphabet::base64url>("MTIz"));
	ASSERT_EQ("MTIzNA%3d%3d", jwt::base::pad<jwt::alphabet::base64url>("MTIzNA"));
}

TEST(BaseTest, Base64Trim) {
	ASSERT_EQ("MQ", jwt::base::trim<jwt::alphabet::base64>("MQ=="));
	ASSERT_EQ("MTI", jwt::base::trim<jwt::alphabet::base64>("MTI="));
	ASSERT_EQ("MTIz", jwt::base::trim<jwt::alphabet::base64>("MTIz"));
	ASSERT_EQ("MTIzNA", jwt::base::trim<jwt::alphabet::base64>("MTIzNA=="));
}

TEST(BaseTest, Base64TrimURL) {
	ASSERT_EQ("MQ", jwt::base::trim<jwt::alphabet::base64url>("MQ%3d%3d"));
	ASSERT_EQ("MTI", jwt::base::trim<jwt::alphabet::base64url>("MTI%3d"));
	ASSERT_EQ("MTIz", jwt::base::trim<jwt::alphabet::base64url>("MTIz"));
	ASSERT_EQ("MTIzNA", jwt::base::trim<jwt::alphabet::base64url>("MTIzNA%3d%3d"));
}
