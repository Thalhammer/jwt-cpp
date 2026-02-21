#include "jwt-cpp/traits/stephenberry-glaze/traits.h"
#include <chrono>
#include <gtest/gtest.h>
#include <set>
#include <sstream>
#include <vector>

// This is the expanded version of the Mustache template you pasted
TEST(StephenberryGlazeTest, BasicClaims) {
	const auto string_claim =
		jwt::basic_claim<jwt::traits::stephenberry_glaze>(jwt::traits::stephenberry_glaze::string_type("string"));
	ASSERT_EQ(string_claim.get_type(), jwt::json::type::string);

	const auto array_claim = jwt::basic_claim<jwt::traits::stephenberry_glaze>(
		std::set<jwt::traits::stephenberry_glaze::string_type>{"string", "string"});
	ASSERT_EQ(array_claim.get_type(), jwt::json::type::array);

	const auto integer_claim = jwt::basic_claim<jwt::traits::stephenberry_glaze>(159816816);
	ASSERT_EQ(integer_claim.get_type(), jwt::json::type::number); // glaze has no integers in it, only doubles
}

TEST(StephenberryGlazeTest, AudienceAsString) {
	jwt::traits::stephenberry_glaze::string_type token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0.WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
	auto decoded = jwt::decode<jwt::traits::stephenberry_glaze>(token);

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

TEST(StephenberryGlazeTest, SetArray) {
	std::vector<int64_t> vect = {100, 20, 10};
	auto token =
		jwt::create<jwt::traits::stephenberry_glaze>()
			.set_payload_claim("test", jwt::basic_claim<jwt::traits::stephenberry_glaze>(vect.begin(), vect.end()))
			.sign(jwt::algorithm::none{});
	ASSERT_EQ(token, "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.");
}

TEST(StephenberryGlazeTest, SetObject) {
	std::istringstream iss{"{\"api-x\": [1]}"};
	jwt::basic_claim<jwt::traits::stephenberry_glaze> object;
	// iss >> object; // THere is no operator >> for string streams in glz::json_t
	object = jwt::basic_claim<jwt::traits::stephenberry_glaze>(
		*glz::read_json<jwt::traits::stephenberry_glaze::value_type>(iss.str()));
	ASSERT_EQ(object.get_type(), jwt::json::type::object);

	auto token = jwt::create<jwt::traits::stephenberry_glaze>()
					 .set_payload_claim("namespace", object)
					 .sign(jwt::algorithm::hs256("test"));
	ASSERT_EQ(token,
			  "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lc3BhY2UiOnsiYXBpLXgiOlsxXX19.F8I6I2RcSF98bKa0IpIz09fRZtHr1CWnWKx2za-tFQA");
}

TEST(StephenberryGlazeTest, VerifyTokenHS256) {
	jwt::traits::stephenberry_glaze::string_type token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";

	const auto decoded_token = jwt::decode<jwt::traits::stephenberry_glaze>(token);
	const auto verify = jwt::verify<jwt::traits::stephenberry_glaze>()
							.allow_algorithm(jwt::algorithm::hs256{"secret"})
							.with_issuer("auth0");
	verify.verify(decoded_token);
}

TEST(StephenberryGlazeTest, VerifyTokenExpirationValid) {
	const auto token = jwt::create<jwt::traits::stephenberry_glaze>()
						   .set_issuer("auth0")
						   .set_issued_at(std::chrono::system_clock::now())
						   .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
						   .sign(jwt::algorithm::hs256{"secret"});

	const auto decoded_token = jwt::decode<jwt::traits::stephenberry_glaze>(token);
	const auto verify = jwt::verify<jwt::traits::stephenberry_glaze>()
							.allow_algorithm(jwt::algorithm::hs256{"secret"})
							.with_issuer("auth0");
	verify.verify(decoded_token);
}

TEST(StephenberryGlazeTest, VerifyTokenExpired) {
	const auto token = jwt::create<jwt::traits::stephenberry_glaze>()
						   .set_issuer("auth0")
						   .set_issued_at(std::chrono::system_clock::now() - std::chrono::seconds{3601})
						   .set_expires_at(std::chrono::system_clock::now() - std::chrono::seconds{1})
						   .sign(jwt::algorithm::hs256{"secret"});

	const auto decoded_token = jwt::decode<jwt::traits::stephenberry_glaze>(token);
	const auto verify = jwt::verify<jwt::traits::stephenberry_glaze>()
							.allow_algorithm(jwt::algorithm::hs256{"secret"})
							.with_issuer("auth0");
	ASSERT_THROW(verify.verify(decoded_token), jwt::error::token_verification_exception);

	std::error_code ec;
	ASSERT_NO_THROW(verify.verify(decoded_token, ec));
	ASSERT_TRUE(!(!ec));
	ASSERT_EQ(ec.category(), jwt::error::token_verification_error_category());
	ASSERT_EQ(ec.value(), static_cast<int>(jwt::error::token_verification_error::token_expired));
}
