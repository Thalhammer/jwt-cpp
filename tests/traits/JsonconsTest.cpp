#define JSONCONS_NO_DEPRECATED

#include "jwt-cpp/traits/danielaparker-jsoncons/defaults.h"

#include <gtest/gtest.h>

TEST(JsonconsTest, BasicClaims) {
	const auto string = jwt::claim(std::string("string"));
	ASSERT_EQ(string.get_type(), jwt::json::type::string);

	const auto array = jwt::claim(std::set<std::string>{"string", "string"});
	ASSERT_EQ(array.get_type(), jwt::json::type::array);

	const auto integer = jwt::claim(159816816);
	ASSERT_EQ(integer.get_type(), jwt::json::type::integer);
}

TEST(JsonconsTest, AudienceAsString) {
	std::string token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0.WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
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

TEST(JsonconsTest, SetArray) {
	std::vector<int64_t> vect = {100, 20, 10};
	auto token =
		jwt::create().set_payload_claim("test", jwt::claim(vect.begin(), vect.end())).sign(jwt::algorithm::none{});
	ASSERT_EQ(token, "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.");
}

TEST(JsonconsTest, SetObject) {
	std::istringstream iss{"{\"api-x\": [1]}"};
	jwt::claim object;
	iss >> object;
	ASSERT_EQ(object.get_type(), jwt::json::type::object);

	auto token = jwt::create().set_payload_claim("namespace", object).sign(jwt::algorithm::hs256("test"));
	ASSERT_EQ(token,
			  "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lc3BhY2UiOnsiYXBpLXgiOlsxXX19.F8I6I2RcSF98bKa0IpIz09fRZtHr1CWnWKx2za-tFQA");
}

TEST(JsonconsTest, VerifyTokenHS256) {
	std::string token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";

	const auto decoded_token = jwt::decode(token);
	const auto verify = jwt::verify().allow_algorithm(jwt::algorithm::hs256{"secret"}).with_issuer("auth0");
	verify.verify(decoded_token);
}

TEST(JsonconsTest, VerifyTokenExpirationValid) {
	const auto token = jwt::create()
						   .set_issuer("auth0")
						   .set_issued_at(std::chrono::system_clock::now())
						   .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
						   .sign(jwt::algorithm::hs256{"secret"});

	const auto decoded_token = jwt::decode(token);
	const auto verify = jwt::verify().allow_algorithm(jwt::algorithm::hs256{"secret"}).with_issuer("auth0");
	verify.verify(decoded_token);
}

TEST(JsonconsTest, VerifyTokenExpired) {
	const auto token = jwt::create()
						   .set_issuer("auth0")
						   .set_issued_at(std::chrono::system_clock::now() - std::chrono::seconds{3601})
						   .set_expires_at(std::chrono::system_clock::now() - std::chrono::seconds{1})
						   .sign(jwt::algorithm::hs256{"secret"});

	const auto decoded_token = jwt::decode(token);
	const auto verify = jwt::verify().allow_algorithm(jwt::algorithm::hs256{"secret"}).with_issuer("auth0");
	ASSERT_THROW(verify.verify(decoded_token), jwt::token_verification_exception);

	std::error_code ec;
	ASSERT_NO_THROW(verify.verify(decoded_token, ec));
	ASSERT_TRUE(!(!ec));
	ASSERT_EQ(ec.category(), jwt::error::token_verification_error_category());
	ASSERT_EQ(ec.value(), static_cast<int>(jwt::error::token_verification_error::token_expired));
}
