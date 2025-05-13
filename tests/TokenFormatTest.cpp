#include "jwt-cpp/jwt.h"
#include <gtest/gtest.h>

TEST(TokenFormatTest, MissingDot) {
	ASSERT_THROW(jwt::decode("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJpc3MiOiJhdXRoMCJ9"), std::invalid_argument);
	ASSERT_THROW(jwt::decode("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0eyJpc3MiOiJhdXRoMCJ9."), std::invalid_argument);
	ASSERT_THROW(jwt::decode("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0eyJpc3MiOiJhdXRoMCJ9"), std::invalid_argument);
}

TEST(TokenFormatTest, InvalidChar) {
	ASSERT_THROW(jwt::decode("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0().eyJpc3MiOiJhdXRoMCJ9."), std::runtime_error);
}

TEST(TokenFormatTest, InvalidJSON) {
	ASSERT_THROW(jwt::decode("YXsiYWxnIjoibm9uZSIsInR5cCI6IkpXUyJ9YQ.eyJpc3MiOiJhdXRoMCJ9."), std::runtime_error);
}

#include "jwt-cpp/traits/nlohmann-json/traits.h"

TEST(TokenFormatTest, GitHubIssue341) {
	std::string const token =
		"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjYXV0aDAiLCJleHAiOjE3MTMzODgxNjgsInN1YiI6InRlc3RfdXNlciJ9."
		"dlAk0mSWk1Clzfi1PMq7Omxun3EyEqh-AAu-fTkpabA67ZKenawAQhZO8glY93flukpJCqHLVtukaes6ZSOjGw";
	auto decoded = jwt::decoded_jwt<jwt::traits::nlohmann_json>(token);

	ASSERT_TRUE(decoded.has_algorithm());
	ASSERT_TRUE(decoded.has_type());
	ASSERT_TRUE(decoded.has_issuer());
	ASSERT_TRUE(decoded.has_subject());

	ASSERT_EQ("ES256", decoded.get_algorithm());
	ASSERT_EQ("JWT", decoded.get_type());
	ASSERT_EQ("cauth0", decoded.get_issuer());
	ASSERT_EQ("test_user", decoded.get_subject());
}
