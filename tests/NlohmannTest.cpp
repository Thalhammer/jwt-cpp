#define DISABLE_PICOJSON // Make sure JWT compiles with this flag

#include <gtest/gtest.h>
#include "jwt-cpp/jwt.h"
#include "nlohmann/json.hpp"

struct nlohmann_traits {
	using json = nlohmann::json;
	using value_type = json;
	using object_type = json::object_t;
	using array_type = json::array_t;
	using string_type = std::string;
	using number_type = double;
	using integer_type = int64_t;
	using boolean_type = bool;

	static jwt::json::type get_type(const json &val) {
		using jwt::json::type;

		if (val.type() == json::value_t::boolean)
			return type::boolean;
		else if (val.type() == json::value_t::number_integer)
			return type::integer;
		else if (val.type() == json::value_t::number_float)
			return type::number;
		else if (val.type() == json::value_t::string)
			return type::string;
		else if (val.type() == json::value_t::array)
			return type::array;
		else if (val.type() == json::value_t::object)
			return type::object;
		else
			throw std::logic_error("invalid type");
	}

	static json::object_t as_object(const json &val) {
		if (val.type() != json::value_t::object)
			throw std::bad_cast();
		return val.get<json::object_t>();
	}

	static std::string as_string(const json &val) {
		if (val.type() != json::value_t::string)
			throw std::bad_cast();
		return val.get<std::string>();
	}

	static json::array_t as_array(const json &val) {
		if (val.type() != json::value_t::array)
			throw std::bad_cast();
		return val.get<json::array_t>();
	}

	static int64_t as_int(const json &val) {
		if (val.type() != json::value_t::number_integer)
			throw std::bad_cast();
		return val.get<int64_t>();
	}

	static bool as_bool(const json &val) {
		if (val.type() != json::value_t::boolean)
			throw std::bad_cast();
		return val.get<bool>();
	}

	static double as_number(const json &val) {
		if (val.type() != json::value_t::number_float)
			throw std::bad_cast();
		return val.get<double>();
	}

	static bool parse(json &val, std::string str) {
		val = json::parse(str.begin(), str.end());
		return true;
	}

	static std::string serialize(const json &val) {
		return val.dump();
	}
};

#define JWT_NHOLMANN_CLAIM_TPL \
	nlohmann::json::value_type, nlohmann::json::object_t, \
	nlohmann::json::array_t, nlohmann::json::string_t, \
	nlohmann::json::number_float_t, \
	nlohmann::json::number_integer_t, \
	nlohmann::json::boolean_t, nlohmann_traits

TEST(NholmannTest, BasicClaims) {
	using nholmann_claim = jwt::basic_claim<nlohmann_traits>;

	const auto string = nholmann_claim(std::string("string"));
	const auto array = nholmann_claim(std::set<std::string>{"string", "string"});
	const auto integer = nholmann_claim(159816816);
}

TEST(NholmannTest, AudienceAsString) {

	std::string token =
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0."
			"WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
	auto decoded = jwt::decode<nlohmann_traits>(token);

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

TEST(NholmannTest, SetArray) {
	std::vector<int64_t> vect = {
		100,
		20,
		10
	};
	auto token = jwt::create<nlohmann_traits>()
		.set_payload_claim("test", jwt::basic_claim<nlohmann_traits>(vect.begin(), vect.end()))
		.sign(jwt::algorithm::none{});
	ASSERT_EQ(token, "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.");
}

TEST(NholmannTest, SetObject) {
	std::istringstream iss{"{\"api-x\": [1]}"};
	jwt::basic_claim<nlohmann_traits> object;
	iss >> object;
	ASSERT_EQ(object.get_type() , jwt::json::type::object);

	auto token = jwt::create<nlohmann_traits>()
		.set_payload_claim("namespace", object)
		.sign(jwt::algorithm::hs256("test"));
	ASSERT_EQ(token, "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lc3BhY2UiOnsiYXBpLXgiOlsxXX19.F8I6I2RcSF98bKa0IpIz09fRZtHr1CWnWKx2za-tFQA");
}

TEST(NholmannTest, VerifyTokenHS256) {
	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";

	auto verify = jwt::verify<jwt::default_clock, nlohmann_traits>({})
		.allow_algorithm(jwt::algorithm::hs256{ "secret" })
		.with_issuer("auth0");

	auto decoded_token = jwt::decode<nlohmann_traits>(token);
	verify.verify(decoded_token);
}
