#include <gtest/gtest.h>
#include "jwt-cpp/jwt.h"

TEST(ClaimTest, AudienceAsString) {
	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0.WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
	auto decoded = jwt::decode(token);

	ASSERT_TRUE(decoded.has_algorithm());
	ASSERT_TRUE(decoded.has_type());
	ASSERT_FALSE(decoded.has_content_type());
	ASSERT_FALSE(decoded.has_key_id());
	ASSERT_FALSE(decoded.has_issuer());
	ASSERT_FALSE(decoded.has_subject());
	ASSERT_TRUE(decoded.has_audience());
	ASSERT_FALSE(decoded.has_expires_at());
	ASSERT_FALSE(decoded.has_not_before());
	ASSERT_FALSE(decoded.has_issued_at());
	ASSERT_FALSE(decoded.has_id());

	ASSERT_EQ("HS256", decoded.get_algorithm());
	ASSERT_EQ("JWT", decoded.get_type());
	auto aud = decoded.get_audience();
	ASSERT_EQ(1, aud.size());
	ASSERT_EQ("test", *aud.begin());
}

TEST(ClaimTest, SetAudienceAsString) {
	auto token = jwt::create()
		.set_type("JWT")
		.set_audience("test")
		.sign(jwt::algorithm::hs256("test"));
	ASSERT_EQ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0.ny5Fa0vzAg7tNL95KWg_ecBNd3XP3tdAzq0SFA6diY4", token);
}

TEST(ClaimTest, SetArray) {
	std::vector<int64_t> vect = {
		100,
		20,
		10
	};
	auto token = jwt::create()
		.set_payload_claim("test", jwt::claim(vect.begin(), vect.end()))
		.sign(jwt::algorithm::none{});
	ASSERT_EQ(token, "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.");
}

TEST(ClaimTest, SetAlgorithm) {
	auto token = jwt::create()
		.set_algorithm("test")
		.sign(jwt::algorithm::none{});

	auto decoded_token = jwt::decode(token);
	ASSERT_EQ(decoded_token.get_algorithm(), "test");
}
