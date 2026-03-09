// Include the generated trait type list for parameterized testing
#include "traits_typelist.h"

template<typename Trait>
class TokenFormatTest : public ::testing::Test {};

TYPED_TEST_SUITE(TokenFormatTest, AllTraitTypes);

TYPED_TEST(TokenFormatTest, MissingDot) {
	EXPECT_THROW(jwt::decode<TypeParam>("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJpc3MiOiJhdXRoMCJ9"),
				 std::invalid_argument);
	EXPECT_THROW(jwt::decode<TypeParam>("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0eyJpc3MiOiJhdXRoMCJ9."),
				 std::invalid_argument);
	EXPECT_THROW(jwt::decode<TypeParam>("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0eyJpc3MiOiJhdXRoMCJ9"),
				 std::invalid_argument);
}

TYPED_TEST(TokenFormatTest, InvalidChar) {
	EXPECT_THROW(jwt::decode<TypeParam>("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0().eyJpc3MiOiJhdXRoMCJ9."),
				 std::runtime_error);
}

TYPED_TEST(TokenFormatTest, InvalidJSON) {
	EXPECT_ANY_THROW(jwt::decode<TypeParam>("YXsiYWxnIjoibm9uZSIsInR5cCI6IkpXUyJ9YQ.eyJpc3MiOiJhdXRoMCJ9."));
}

TYPED_TEST(TokenFormatTest, GitHubIssue341) {
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
