#define JWT_DISABLE_PICOJSON
#include "jwt-cpp/jwt.h"

#include <boost/json.hpp>
#include <boost/json/src.hpp>
#include <gtest/gtest.h>

#include <chrono>
#include <iostream>

namespace json = boost::json;

struct boostjson_traits {
	using value_type = json::value;
	using object_type = json::object;
	using array_type = json::array;
	using string_type = std::string;
	using number_type = double;
	using integer_type = std::int64_t;
	using boolean_type = bool;

	static jwt::json::type get_type(const value_type& val) {
		using jwt::json::type;

		if (val.kind() == json::kind::bool_) return type::boolean;
		if (val.kind() == json::kind::int64) return type::integer;
		if (val.kind() == json::kind::uint64) // boost internally tracks two types of integers
			return type::integer;
		if (val.kind() == json::kind::double_) return type::number;
		if (val.kind() == json::kind::string) return type::string;
		if (val.kind() == json::kind::array) return type::array;
		if (val.kind() == json::kind::object) return type::object;

		throw std::logic_error("invalid type");
	}

	static object_type as_object(const value_type& val) {
		if (val.kind() != json::kind::object) throw std::bad_cast();
		return val.get_object();
	}

	static array_type as_array(const value_type& val) {
		if (val.kind() != json::kind::array) throw std::bad_cast();
		return val.get_array();
	}

	static string_type as_string(const value_type& val) {
		if (val.kind() != json::kind::string) throw std::bad_cast();
		return string_type{val.get_string()};
	}

	static integer_type as_int(const value_type& val) {
		switch (val.kind()) {
		case json::kind::int64: return val.get_int64();
		case json::kind::uint64: return static_cast<int64_t>(val.get_uint64());
		default: throw std::bad_cast();
		}
	}

	static boolean_type as_bool(const value_type& val) {
		if (val.kind() != json::kind::bool_) throw std::bad_cast();
		return val.get_bool();
	}

	static number_type as_number(const value_type& val) {
		if (val.kind() != json::kind::double_) throw std::bad_cast();
		return val.get_double();
	}

	static bool parse(value_type& val, string_type str) {
		val = json::parse(str);
		return true;
	}

	static std::string serialize(const value_type& val) { return json::serialize(val); }
};

TEST(BoostJSONTest, BasicClaims) {
	using boostjson_claim = jwt::basic_claim<boostjson_traits>;

	const auto string = boostjson_claim(boostjson_traits::string_type("string"));
	const auto array = boostjson_claim(std::set<boostjson_traits::string_type>{"string", "string"});
	const auto integer = boostjson_claim(boostjson_traits::value_type{159816816});
}

TEST(BoostJSONTest, AudienceAsString) {
	boostjson_traits::string_type token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0."
										  "WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
	auto decoded = jwt::decode<boostjson_traits>(token);

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

TEST(BoostJSONTest, SetArray) {
	std::vector<int64_t> vect = {100, 20, 10};
	auto token = jwt::create<boostjson_traits>()
					 .set_payload_claim("test", jwt::basic_claim<boostjson_traits>(vect.begin(), vect.end()))
					 .sign(jwt::algorithm::none{});
	ASSERT_EQ(token, "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.");
}

TEST(BoostJSONTest, SetObject) {
	jwt::basic_claim<boostjson_traits> object{json::parse("{\"api-x\": [1]}")};
	ASSERT_EQ(object.get_type(), jwt::json::type::object);

	auto token =
		jwt::create<boostjson_traits>().set_payload_claim("namespace", object).sign(jwt::algorithm::hs256("test"));
	ASSERT_EQ(token,
			  "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lc3BhY2UiOnsiYXBpLXgiOlsxXX19.F8I6I2RcSF98bKa0IpIz09fRZtHr1CWnWKx2za-tFQA");
}

TEST(BoostJSONTest, VerifyTokenHS256) {
	boostjson_traits::string_type token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";

	auto verify = jwt::verify<jwt::default_clock, boostjson_traits>({})
					  .allow_algorithm(jwt::algorithm::hs256{"secret"})
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<boostjson_traits>(token);
	verify.verify(decoded_token);
}

TEST(BoostJSONTest, VerifyTokenExpirationValid) {
	const auto token = jwt::create<boostjson_traits>()
						   .set_issuer("auth0")
						   .set_issued_at(std::chrono::system_clock::now())
						   .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
						   .sign(jwt::algorithm::hs256{"secret"});

	auto verify = jwt::verify<jwt::default_clock, boostjson_traits>({})
					  .allow_algorithm(jwt::algorithm::hs256{"secret"})
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<boostjson_traits>(token);
	verify.verify(decoded_token);
}

TEST(BoostJSONTest, VerifyTokenExpired) {
	const auto token = jwt::create<boostjson_traits>()
						   .set_issuer("auth0")
						   .set_issued_at(std::chrono::system_clock::now() - std::chrono::seconds{3601})
						   .set_expires_at(std::chrono::system_clock::now() - std::chrono::seconds{1})
						   .sign(jwt::algorithm::hs256{"secret"});

	auto verify = jwt::verify<jwt::default_clock, boostjson_traits>({})
					  .allow_algorithm(jwt::algorithm::hs256{"secret"})
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<boostjson_traits>(token);
	ASSERT_THROW(verify.verify(decoded_token), jwt::token_verification_exception);
	std::error_code ec;
	ASSERT_NO_THROW(verify.verify(decoded_token, ec));
	ASSERT_TRUE(!(!ec));
	ASSERT_EQ(ec.category(), jwt::error::token_verification_error_category());
	ASSERT_EQ(ec.value(), static_cast<int>(jwt::error::token_verification_error::token_expired));
}
