// Include the generated trait type list for parameterized testing
#include "traits_typelist.h"

#include <gmock/gmock.h>
using ::testing::AnyOf;

template<typename Trait>
class ClaimTest : public ::testing::Test {};

TYPED_TEST_SUITE(ClaimTest, AllTraitTypes);

TYPED_TEST(ClaimTest, AudienceAsString) {
	std::string const token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0.WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
	auto decoded = jwt::decode<TypeParam>(token);

	EXPECT_TRUE(decoded.has_algorithm());
	EXPECT_TRUE(decoded.has_type());
	EXPECT_FALSE(decoded.has_content_type());
	EXPECT_FALSE(decoded.has_key_id());
	EXPECT_FALSE(decoded.has_issuer());
	EXPECT_FALSE(decoded.has_subject());
	EXPECT_TRUE(decoded.has_audience());
	EXPECT_FALSE(decoded.has_expires_at());
	EXPECT_FALSE(decoded.has_not_before());
	EXPECT_FALSE(decoded.has_issued_at());
	EXPECT_FALSE(decoded.has_id());

	EXPECT_EQ("HS256", decoded.get_algorithm());
	EXPECT_EQ("JWT", decoded.get_type());
	auto aud = decoded.get_audience();
	EXPECT_EQ(1, aud.size());
	EXPECT_EQ("test", *aud.begin());
}

TYPED_TEST(ClaimTest, SetAudienceAsString) {
	auto token = jwt::create<TypeParam>().set_type("JWT").set_audience("test").sign(jwt::algorithm::hs256("test"));
	// Header claim order does not matter, so check both possibilities
	EXPECT_THAT(
		token,
		AnyOf("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0.ny5Fa0vzAg7tNL95KWg_ecBNd3XP3tdAzq0SFA6diY4",
			  "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJ0ZXN0In0.3PVcrRz3ipFzs8vJaIlRNViUae48dIXWv5FLX5PJDzA"));
}

TYPED_TEST(ClaimTest, AudienceAsSet) {
	std::string const token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWQiOlsidGVzdCIsInRlc3QyIl19.";
	auto decoded = jwt::decode<TypeParam>(token);

	EXPECT_TRUE(decoded.has_algorithm());
	EXPECT_TRUE(decoded.has_type());
	EXPECT_FALSE(decoded.has_content_type());
	EXPECT_FALSE(decoded.has_key_id());
	EXPECT_FALSE(decoded.has_issuer());
	EXPECT_FALSE(decoded.has_subject());
	EXPECT_TRUE(decoded.has_audience());
	EXPECT_FALSE(decoded.has_expires_at());
	EXPECT_FALSE(decoded.has_not_before());
	EXPECT_FALSE(decoded.has_issued_at());
	EXPECT_FALSE(decoded.has_id());

	EXPECT_EQ("none", decoded.get_algorithm());
	EXPECT_EQ("JWT", decoded.get_type());
	auto aud = decoded.get_audience();
	EXPECT_EQ(2, aud.size());
	EXPECT_TRUE(aud.count("test") > 0);
	EXPECT_TRUE(aud.count("test2") > 0);
}

TYPED_TEST(ClaimTest, SetAudienceAsSet) {
	auto token = jwt::create<TypeParam>()
					 .set_type("JWT")
					 .set_audience(typename TypeParam::array_type{typename TypeParam::value_type("test"),
																  typename TypeParam::value_type("test2")})
					 .sign(jwt::algorithm::none{});

	// Header claim order does not matter, so check both possibilities
	EXPECT_THAT(token, AnyOf("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWQiOlsidGVzdCIsInRlc3QyIl19.",
							 "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOlsidGVzdCIsInRlc3QyIl19."));
}

TYPED_TEST(ClaimTest, SetArray) {
	std::vector<int64_t> vect = {100, 20, 10};
	auto token = jwt::create<TypeParam>()
					 .set_payload_claim("test", jwt::basic_claim<TypeParam>(vect.begin(), vect.end()))
					 .sign(jwt::algorithm::none{});
	EXPECT_EQ(token, "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.");
}

TYPED_TEST(ClaimTest, SetObject) {
	std::istringstream iss{"{\"api-x\": [1]}"};
	jwt::basic_claim<TypeParam> object;
	iss >> object;
	EXPECT_EQ(object.get_type(), jwt::json::type::object);

	auto token = jwt::create<TypeParam>().set_payload_claim("namespace", object).sign(jwt::algorithm::hs256("test"));
	EXPECT_EQ(token,
			  "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lc3BhY2UiOnsiYXBpLXgiOlsxXX19.F8I6I2RcSF98bKa0IpIz09fRZtHr1CWnWKx2za-tFQA");
}

TYPED_TEST(ClaimTest, EmptyToken) {
	ASSERT_NO_THROW(jwt::create<TypeParam>().sign(jwt::algorithm::none{}));
	auto token = jwt::create<TypeParam>().sign(jwt::algorithm::none{});
	EXPECT_EQ(token, "eyJhbGciOiJub25lIn0.e30.");
}

TYPED_TEST(ClaimTest, SetAlgorithm) {
	ASSERT_NO_THROW(jwt::create<TypeParam>().set_algorithm("test").sign(jwt::algorithm::none{}));
	auto token = jwt::create<TypeParam>().set_algorithm("test").sign(jwt::algorithm::none{});

	ASSERT_NO_THROW(jwt::decode<TypeParam>(token));
	auto decoded_token = jwt::decode<TypeParam>(token);
	EXPECT_EQ(decoded_token.get_algorithm(), "test");
}

TYPED_TEST(ClaimTest, AsInt) {
	jwt::basic_claim<TypeParam> c(typename TypeParam::value_type(static_cast<int64_t>(10)));
	EXPECT_EQ(c.as_integer(), 10);
}

TYPED_TEST(ClaimTest, AsDate) {
	jwt::basic_claim<TypeParam> c(typename TypeParam::value_type(static_cast<int64_t>(10)));
	EXPECT_EQ(c.as_date(), std::chrono::system_clock::from_time_t(10));
}

TEST(ClaimTest, PicoJSONTraitsAccessorsThrow) {
	jwt::traits::kazuho_picojson::value_type val;
	EXPECT_THROW(jwt::traits::kazuho_picojson::as_array(val), std::bad_cast);
	EXPECT_THROW(jwt::traits::kazuho_picojson::as_boolean(val), std::bad_cast);
	EXPECT_THROW(jwt::traits::kazuho_picojson::as_integer(val), std::bad_cast);
	EXPECT_THROW(jwt::traits::kazuho_picojson::as_number(val), std::bad_cast);
	EXPECT_THROW(jwt::traits::kazuho_picojson::as_object(val), std::bad_cast);
	EXPECT_THROW(jwt::traits::kazuho_picojson::as_string(val), std::bad_cast);
	EXPECT_THROW(jwt::traits::kazuho_picojson::get_type(val), std::logic_error);
}

TEST(ClaimTest, PicoJSONTraitsAsBool) {
	jwt::traits::kazuho_picojson::value_type val(true);
	EXPECT_EQ(jwt::traits::kazuho_picojson::as_boolean(val), true);
	EXPECT_EQ(jwt::traits::kazuho_picojson::get_type(val), jwt::json::type::boolean);
}

TEST(ClaimTest, PicoJSONTraitsAsDouble) {
	jwt::traits::kazuho_picojson::value_type val(10.0);
	EXPECT_EQ(jwt::traits::kazuho_picojson::as_number(val), (int)10);
	EXPECT_EQ(jwt::traits::kazuho_picojson::get_type(val), jwt::json::type::number);
}

TEST(ClaimTest, MapOfClaim) {
	using map = jwt::details::map_of_claims<jwt::traits::kazuho_picojson>;
	EXPECT_THROW(map::parse_claims(R"##(__ not json __)##"), jwt::error::invalid_json_exception);
	const map claims{
		map::parse_claims(R"##({ "array": [1], "string" : "hello world", "number": 9.9, "bool": true})##")};

	EXPECT_TRUE(claims.has_claim("array"));
	EXPECT_TRUE(claims.has_claim("string"));
	EXPECT_TRUE(claims.has_claim("number"));
	EXPECT_TRUE(claims.has_claim("bool"));
	EXPECT_FALSE(claims.has_claim("__missing__"));

	EXPECT_EQ(map::basic_claim_t{claims.get_claim("array").as_array().at(0)}.as_integer(), (int)1);
	EXPECT_EQ(claims.get_claim("string").as_string(), "hello world");
	EXPECT_EQ(claims.get_claim("number").as_number(), 9.9);
	EXPECT_EQ(claims.get_claim("bool").as_boolean(), true);
	EXPECT_THROW(claims.get_claim("__missing__"), jwt::error::claim_not_present_exception);
}
