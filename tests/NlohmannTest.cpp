#include <gtest/gtest.h>
#include "jwt-cpp/jwt.h"
#include "nlohmann/json.hpp"

template<typename json_type = nlohmann::json>
struct nlohmann_traits {
	using json = json_type;
	using value_enum = nlohmann::detail::value_t;

	static jwt::json::type get_type(const typename json::value_t &val) {
		using jwt::json::type;

		if (val.type() == value_enum::null)
			return type::null;
		else if (val.type() == value_enum::boolean)
			return type::boolean;
		else if (val.type() == value_enum::number_integer)
			return type::integer;
		else if (val.type() == value_enum::number_float)
			return type::number;
		else if (val.type() == value_enum::string)
			return type::string;
		else if (val.type() == value_enum::array)
			return type::array;
		else if (val.type() == value_enum::object)
			return type::object;
		else
			throw std::logic_error("invalid type");
	}

	static typename json::object_t as_object(const typename json::value_t &val) {
		if (val.type() != value_enum::object)
			throw std::bad_cast();
		return val.get<typename json::object_t>();
	}

	static typename json::string_t as_string(const typename json::value_t &val) {
		if (val.type() != value_enum::string)
			throw std::bad_cast();
		return val.get<typename json::string_t>();
	}

	static typename json::array_t as_array(const typename json::value_t &val) {
		if (val.type() != value_enum::array)
			throw std::bad_cast();
		return val.get<typename json::array_t>();
	}

	static std::set<typename json::string_t> as_set(const typename json::value_t &val) {
		std::set<typename json::string_t> res;
		for (auto &e : as_array(val)) {
			if (val.type() != value_enum::string)
				throw std::bad_cast();
			res.insert(e.get<typename json::string_t>());
		}
		return res;
	}

	static typename json::number_integer_t as_int(const typename json::value_t &val) {
		if (val.type() != value_enum::number_integer)
			throw std::bad_cast();
		return val.get<typename json::number_integer_t>();
	}

	static typename json::boolean_t as_bool(const typename json::value_t &val) {
		if (val.type() != value_enum::boolean)
			throw std::bad_cast();
		return val.get<typename json::boolean_t>();
	}

	static typename json::number_float_t as_number(const typename json::value_t &val) {
		if (val.type() != value_enum::number_float)
			throw std::bad_cast();
		return val.get<typename json::number_float_t>();
	}

	static bool parse(typename json::value_t &val, typename json::string_t str) {
		val = json::parse(str.begin(), str.end());
		return true;
	}

	static typename json::string_t serialize(const typename json::value_t &val) {
		return val.dump();
	}
};

#define JWT_NHOLMANN_CLAIM_TPL \
	nlohmann::json::value_type, nlohmann::json::object_t, \
	nlohmann::json::array_t, nlohmann::json::string_t, \
	nlohmann::json::boolean_t, \
	nlohmann::json::number_integer_t, \
	nlohmann::json::number_float_t, nlohmann_traits<>

TEST(NholmannTest, BasicClaims) {
	using nholmann_claim =
			jwt::basic_claim<JWT_NHOLMANN_CLAIM_TPL>;

	const auto string = nholmann_claim(std::string("string"));
	const auto array = nholmann_claim(std::set<std::string>{"string", "string"});
	const auto integer = nholmann_claim(159816816);
}

TEST(NholmannTest, AudienceAsString) {

	std::string token =
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0."
			"WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
	auto decoded =
			jwt::decode<JWT_NHOLMANN_CLAIM_TPL>(token);

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
	auto token = jwt::create<JWT_NHOLMANN_CLAIM_TPL>()
		.set_payload_claim("test", jwt::basic_claim<JWT_NHOLMANN_CLAIM_TPL>(vect.begin(), vect.end()))
		.sign(jwt::algorithm::none{});
	ASSERT_EQ(token, "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.");
}

TEST(NholmannTest, SetObject) {
	std::istringstream iss{"{\"api-x\": [1]}"};
	jwt::basic_claim<JWT_NHOLMANN_CLAIM_TPL> object;
	iss >> object;
	ASSERT_EQ(object.get_type() , jwt::json::type::object);

	auto token = jwt::create<JWT_NHOLMANN_CLAIM_TPL>()
		.set_payload_claim("namespace", object)
		.sign(jwt::algorithm::hs256("test"));
	ASSERT_EQ(token, "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lc3BhY2UiOnsiYXBpLXgiOlsxXX19.F8I6I2RcSF98bKa0IpIz09fRZtHr1CWnWKx2za-tFQA");
}

TEST(NholmannTest, VerifyTokenHS256) {
	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";

	auto verify = jwt::verify<jwt::default_clock, JWT_NHOLMANN_CLAIM_TPL>({})
		.allow_algorithm(jwt::algorithm::hs256{ "secret" })
		.with_issuer("auth0");

	auto decoded_token = jwt::decode<JWT_NHOLMANN_CLAIM_TPL>(token);
	verify.verify(decoded_token);
}

using wide_json = nlohmann::basic_json<
							std::map, std::vector,std::wstring, bool,
							std::int64_t, std::uint64_t, double>;

#define JWT_NHOLMANN_WIDE_CLAIM_TPL \
	wide_json::value_type, wide_json::object_t, \
	wide_json::array_t, wide_json::string_t, \
	wide_json::boolean_t, \
	wide_json::number_integer_t, \
	wide_json::number_float_t, nlohmann_traits<wide_json>

TEST(NholmannWideTest, AudienceAsString) {

	std::wstring token =
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0."
			"WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
	auto decoded =
			jwt::decode<JWT_NHOLMANN_WIDE_CLAIM_TPL>(token);

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

TEST(NholmannWideTest, SetArray) {
	std::vector<int64_t> vect = {
		100,
		20,
		10
	};
	auto token = jwt::create<JWT_NHOLMANN_WIDE_CLAIM_TPL>()
		.set_payload_claim("test", jwt::basic_claim<JWT_NHOLMANN_WIDE_CLAIM_TPL>(vect.begin(), vect.end()))
		.sign(jwt::algorithm::none{});
	ASSERT_EQ(token, "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.");
}

TEST(NholmannWideTest, SetObject) {
	std::istringstream iss{"{\"api-x\": [1]}"};
	jwt::basic_claim<JWT_NHOLMANN_WIDE_CLAIM_TPL> object;
	iss >> object;
	ASSERT_EQ(object.get_type() , jwt::json::type::object);

	auto token = jwt::create<JWT_NHOLMANN_WIDE_CLAIM_TPL>()
		.set_payload_claim("namespace", object)
		.sign(jwt::algorithm::hs256("test"));
	ASSERT_EQ(token, "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lc3BhY2UiOnsiYXBpLXgiOlsxXX19.F8I6I2RcSF98bKa0IpIz09fRZtHr1CWnWKx2za-tFQA");
}

TEST(NholmannWideTest, VerifyTokenHS256) {
	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";

	auto verify = jwt::verify<jwt::default_clock, JWT_NHOLMANN_WIDE_CLAIM_TPL>({})
		.allow_algorithm(jwt::algorithm::hs256{ "secret" })
		.with_issuer("auth0");

	auto decoded_token = jwt::decode<JWT_NHOLMANN_WIDE_CLAIM_TPL>(token);
	verify.verify(decoded_token);
}
