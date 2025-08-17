#include "jwt-cpp/traits/reflect-cpp/traits.h"

#include <gtest/gtest.h>

using jwt::algorithm::hs256;

TEST(ReflectCppTest, BasicClaims) {
	const auto string = jwt::basic_claim<jwt::traits::reflect_cpp>(jwt::traits::reflect_cpp::string_type("string"));
	ASSERT_EQ(string.get_type(), jwt::json::type::string);

	const auto array = jwt::basic_claim<jwt::traits::reflect_cpp>(std::set<std::string>{"string", "string"});
	ASSERT_EQ(array.get_type(), jwt::json::type::array);

	const auto integer = jwt::basic_claim<jwt::traits::reflect_cpp>(159816816);
	ASSERT_EQ(integer.get_type(), jwt::json::type::integer);
}

TEST(ReflectCppTest, AudienceAsString) {
	jwt::traits::reflect_cpp::string_type token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0.WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
	auto decoded = jwt::decode<jwt::traits::reflect_cpp>(token);

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

TEST(ReflectCppTest, SetArray) {
	// Build the array via the trait first
	jwt::traits::reflect_cpp::array_type arr{100, 20, 10};

	jwt::traits::reflect_cpp::value_type value(arr);
	jwt::basic_claim<jwt::traits::reflect_cpp> array_claim(value);

	// Use the reflect-cpp trait for create()
	auto token =
		jwt::create<jwt::traits::reflect_cpp>().set_payload_claim("test", array_claim).sign(jwt::algorithm::none{});

	ASSERT_EQ(token, "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.");
}

TEST(ReflectCppTest, SetObject) {
	// Parse JSON into the trait's value_type
	jwt::traits::reflect_cpp::value_type value;
	ASSERT_TRUE(jwt::traits::reflect_cpp::parse(value, "{\"api-x\": [1]}"));

	// Wrap into a claim and verify type
	jwt::basic_claim<jwt::traits::reflect_cpp> object(value);
	ASSERT_EQ(object.get_type(), jwt::json::type::object);

	// Build a token using the reflect-cpp trait explicitly
	auto token = jwt::create<jwt::traits::reflect_cpp>()
					 .set_payload_claim("namespace", object)
					 .sign(jwt::algorithm::hs256("test"));

	ASSERT_EQ(token,
			  "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lc3BhY2UiOnsiYXBpLXgiOlsxXX19.F8I6I2RcSF98bKa0IpIz09fRZtHr1CWnWKx2za-tFQA");
}

TEST(ReflectCppTest, VerifyTokenHS256) {
	jwt::traits::reflect_cpp::string_type token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";

	const auto decoded = jwt::decode<jwt::traits::reflect_cpp>(token);
	const auto verify =
		jwt::verify<jwt::traits::reflect_cpp>().allow_algorithm(jwt::algorithm::hs256{"secret"}).with_issuer("auth0");

	ASSERT_NO_THROW(verify.verify(decoded));
}

TEST(ReflectCppTest, VerifyTokenExpirationValid) {
	const auto token = jwt::create<jwt::traits::reflect_cpp>()
						   .set_issuer("auth0")
						   .set_issued_at(std::chrono::system_clock::now())
						   .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
						   .sign(jwt::algorithm::hs256{"secret"});

	const auto decoded = jwt::decode<jwt::traits::reflect_cpp>(token);
	const auto verify =
		jwt::verify<jwt::traits::reflect_cpp>().allow_algorithm(jwt::algorithm::hs256{"secret"}).with_issuer("auth0");

	ASSERT_NO_THROW(verify.verify(decoded));
}

TEST(ReflectCppTest, VerifyTokenExpirationInValid) {
	const auto token = jwt::create<jwt::traits::reflect_cpp>()
						   .set_issuer("auth0")
						   .set_issued_now()
						   .set_expires_in(std::chrono::seconds{3600})
						   .sign(jwt::algorithm::hs256{"secret"});

	const auto decoded = jwt::decode<jwt::traits::reflect_cpp>(token);
	const auto verify =
		jwt::verify<jwt::traits::reflect_cpp>().allow_algorithm(jwt::algorithm::hs256{"secret"}).with_issuer("auth0");

	ASSERT_NO_THROW(verify.verify(decoded));
}

TEST(ReflectCppTest, VerifyTokenExpired) {
	const auto token = jwt::create<jwt::traits::reflect_cpp>()
						   .set_issuer("auth0")
						   .set_issued_at(std::chrono::system_clock::now() - std::chrono::seconds{3601})
						   .set_expires_at(std::chrono::system_clock::now() - std::chrono::seconds{1})
						   .sign(jwt::algorithm::hs256{"secret"});

	const auto decoded = jwt::decode<jwt::traits::reflect_cpp>(token);
	const auto verify =
		jwt::verify<jwt::traits::reflect_cpp>().allow_algorithm(jwt::algorithm::hs256{"secret"}).with_issuer("auth0");

	ASSERT_THROW(verify.verify(decoded), jwt::error::token_verification_exception);

	std::error_code errcode;
	ASSERT_NO_THROW(verify.verify(decoded, errcode));
	ASSERT_TRUE(errcode); // non-zero
	ASSERT_EQ(errcode.category(), jwt::error::token_verification_error_category());
	ASSERT_EQ(errcode.value(), static_cast<int>(jwt::error::token_verification_error::token_expired));
}

TEST(ReflectCppTest, VerifyArray) {
	jwt::traits::reflect_cpp::string_type token = "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.";
	const auto decoded = jwt::decode<jwt::traits::reflect_cpp>(token);

	// Build array value_type via the trait
	jwt::traits::reflect_cpp::array_type arr{100, 20, 10};

	jwt::basic_claim<jwt::traits::reflect_cpp> array_claim{jwt::traits::reflect_cpp::value_type(arr)};

	const auto verify =
		jwt::verify<jwt::traits::reflect_cpp>().allow_algorithm(jwt::algorithm::none{}).with_claim("test", array_claim);

	ASSERT_NO_THROW(verify.verify(decoded));
}

TEST(ReflectCppTest, VerifyObject) {
	jwt::traits::reflect_cpp::string_type token =
		"eyJhbGciOiJIUzI1NiJ9.eyJuYW1lc3BhY2UiOnsiYXBpLXgiOlsxXX19.F8I6I2RcSF98bKa0IpIz09fRZtHr1CWnWKx2za-tFQA";
	const auto decoded_token = jwt::decode<jwt::traits::reflect_cpp>(token);

	// Parse into reflect-cpp's JSON value, then wrap as a claim
	jwt::traits::reflect_cpp::value_type value;
	ASSERT_TRUE(jwt::traits::reflect_cpp::parse(value, "{\"api-x\": [1]}"));
	jwt::basic_claim<jwt::traits::reflect_cpp> object_claim(value);

	// Use the reflect-cpp trait for verify(), too
	const auto verify =
		jwt::verify<jwt::traits::reflect_cpp>().allow_algorithm(hs256("test")).with_claim("namespace", object_claim);

	ASSERT_NO_THROW(verify.verify(decoded_token));
}
