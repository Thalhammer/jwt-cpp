#define JWT_DISABLE_PICOJSON
#define JSONCONS_NO_DEPRECATED

#include "jwt-cpp/jwt.h"

#include <gtest/gtest.h>
#include <jsoncons/json.hpp>

#include <sstream>

struct jsoncons_traits {
	using json = jsoncons::json;
	using value_type = json;
	struct object_type : json::object {
		using value_type = key_value_type;
		using mapped_type = key_value_type::
			value_type; // https://github.com/danielaparker/jsoncons/commit/1b1ceeb572f9a2db6d37cff47ac78a4f14e072e2#commitcomment-45391411

		object_type() = default;
		object_type(const object_type&) = default;
		object_type(const json::object& o) : json::object(o) {}
		object_type(object_type&&) = default;
		object_type(json::object&& o) : json::object(o) {}
		object_type& operator=(const object_type& o) {
			// avoid private deleted copy operator= https://github.com/danielaparker/jsoncons/pull/298
			object_type t(static_cast<const json::object&>(o));
			(*this) = std::move(t);
			return *this;
		}
		object_type& operator=(object_type&& o) noexcept {
			swap(o);
			return *this;
		}

		mapped_type& operator[](const key_type& key) {
			auto ret = try_emplace(
				key); // https://github.com/microsoft/STL/blob/2914b4301c59dc7ffc09d16ac6f7979fde2b7f2c/stl/inc/map#L325
			return ret.first->value();
		}
		mapped_type& operator[](key_type&& key) {
			auto ret = try_emplace(key);
			return ret.first->value();
		}

		const mapped_type& at(const key_type& key) const {
			auto target = find(key);
			if (target != end()) { return target->value(); }

			std::out_of_range("invalid key");
		}

		size_t count(const key_type& key) const {
			size_t ret = 0;
			for (const_iterator first = begin(); first != end(); ++first) {
				if (first->key() == key) { ++ret; }
			}
			return ret;
		}
	};
	using array_type = json::array;
	using string_type = std::string; // current limitation of traits implementation
	using number_type = double;
	using integer_type = int64_t;
	using boolean_type = bool;

	static jwt::json::type get_type(const json& val) {
		using jwt::json::type;

		if (val.type() == jsoncons::json_type::bool_value) return type::boolean;
		if (val.type() == jsoncons::json_type::int64_value) return type::integer;
		if (val.type() == jsoncons::json_type::uint64_value) return type::integer;
		if (val.type() == jsoncons::json_type::half_value) return type::number;
		if (val.type() == jsoncons::json_type::double_value) return type::number;
		if (val.type() == jsoncons::json_type::string_value) return type::string;
		if (val.type() == jsoncons::json_type::array_value) return type::array;
		if (val.type() == jsoncons::json_type::object_value) return type::object;

		throw std::logic_error("invalid type");
	}

	static object_type as_object(const json& val) {
		if (val.type() != jsoncons::json_type::object_value) throw std::bad_cast();
		return object_type(val.object_value());
	}

	static array_type as_array(const json& val) {
		if (val.type() != jsoncons::json_type::array_value) throw std::bad_cast();
		return val.array_value();
	}

	static string_type as_string(const json& val) {
		if (val.type() != jsoncons::json_type::string_value) throw std::bad_cast();
		return val.as_string();
	}

	static number_type as_number(const json& val) {
		if (get_type(val) != jwt::json::type::number) throw std::bad_cast();
		return val.as_double();
	}

	static integer_type as_int(const json& val) {
		if (get_type(val) != jwt::json::type::integer) throw std::bad_cast();
		return val.as<integer_type>();
	}

	static boolean_type as_bool(const json& val) {
		if (val.type() != jsoncons::json_type::bool_value) throw std::bad_cast();
		return val.as_bool();
	}

	static bool parse(json& val, std::string str) {
		val = json::parse(str);
		return true;
	}

	static std::string serialize(const json& val) {
		std::ostringstream os;
		os << jsoncons::print(val);
		return os.str();
	}
};

TEST(JsonconsTest, BasicClaims) {
	using jsoncons_claim = jwt::basic_claim<jsoncons_traits>;

	const auto string = jsoncons_claim(std::string("string"));
	const auto array = jsoncons_claim(std::set<std::string>{"string", "string"});
	const auto integer = jsoncons_claim(159816816);
}

TEST(JsonconsTest, AudienceAsString) {

	std::string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0."
						"WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
	auto decoded = jwt::decode<jsoncons_traits>(token);

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
	auto token = jwt::create<jsoncons_traits>()
					 .set_payload_claim("test", jwt::basic_claim<jsoncons_traits>(vect.begin(), vect.end()))
					 .sign(jwt::algorithm::none{});
	ASSERT_EQ(token, "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjpbMTAwLDIwLDEwXX0.");
}

TEST(JsonconsTest, SetObject) {
	std::istringstream iss{"{\"api-x\": [1]}"};
	jwt::basic_claim<jsoncons_traits> object;
	iss >> object;
	ASSERT_EQ(object.get_type(), jwt::json::type::object);

	auto token =
		jwt::create<jsoncons_traits>().set_payload_claim("namespace", object).sign(jwt::algorithm::hs256("test"));
	ASSERT_EQ(token,
			  "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lc3BhY2UiOnsiYXBpLXgiOlsxXX19.F8I6I2RcSF98bKa0IpIz09fRZtHr1CWnWKx2za-tFQA");
}

TEST(JsonconsTest, VerifyTokenHS256) {
	std::string token =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";

	auto verify = jwt::verify<jwt::default_clock, jsoncons_traits>({})
					  .allow_algorithm(jwt::algorithm::hs256{"secret"})
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<jsoncons_traits>(token);
	verify.verify(decoded_token);
}

TEST(JsonconsTest, VerifyTokenExpirationValid) {
	const auto token = jwt::create<jsoncons_traits>()
						   .set_issuer("auth0")
						   .set_issued_at(std::chrono::system_clock::now())
						   .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
						   .sign(jwt::algorithm::hs256{"secret"});

	auto verify = jwt::verify<jwt::default_clock, jsoncons_traits>({})
					  .allow_algorithm(jwt::algorithm::hs256{"secret"})
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<jsoncons_traits>(token);
	verify.verify(decoded_token);
}

TEST(JsonconsTest, VerifyTokenExpired) {
	const auto token = jwt::create<jsoncons_traits>()
						   .set_issuer("auth0")
						   .set_issued_at(std::chrono::system_clock::now() - std::chrono::seconds{3601})
						   .set_expires_at(std::chrono::system_clock::now() - std::chrono::seconds{1})
						   .sign(jwt::algorithm::hs256{"secret"});

	auto verify = jwt::verify<jwt::default_clock, jsoncons_traits>({})
					  .allow_algorithm(jwt::algorithm::hs256{"secret"})
					  .with_issuer("auth0");

	auto decoded_token = jwt::decode<jsoncons_traits>(token);
	ASSERT_THROW(verify.verify(decoded_token), jwt::token_verification_exception);
	std::error_code ec;
	ASSERT_NO_THROW(verify.verify(decoded_token, ec));
	ASSERT_TRUE(!(!ec));
	ASSERT_EQ(ec.category(), jwt::error::token_verification_error_category());
	ASSERT_EQ(ec.value(), static_cast<int>(jwt::error::token_verification_error::token_expired));
}
