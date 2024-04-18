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

TEST(TokenFormatTEst, Issue343) {
	std::string token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjYXV0aDAiLCJleHAiOjE3MTMzODgxNjgsInN1YiI6InRlc3RfdXNlciJ9.dlAk0mSWk1Clzfi1PMq7Omxun3EyEqh-AAu-fTkpabA67ZKenawAQhZO8glY93flukpJCqHLVtukaes6ZSOjGw";
	auto decoded = jwt::decoded_jwt<jwt::traits::nlohmann_json> decoded(token);
	ASSERT_TRUE(decoded.has_algorithm());
}
