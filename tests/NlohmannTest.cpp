#include "jwt-cpp/jwt.h"
#include "nlohmann/json.hpp"
#include <gtest/gtest.h>

struct nlohmann_traits {
  using json = nlohmann::json;

  static jwt::json::type get_type(const json &val) {
    using jwt::json::type;

    if (val.type() == json::value_t::null)
      return type::null;
    else if (val.type() == json::value_t::boolean)
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

  static std::set<std::string> as_set(const json &val) {
    std::set<std::string> res;
    for (auto &e : as_array(val)) {
      if (val.type() != json::value_t::string)
        throw std::bad_cast();
      res.insert(e.get<std::string>());
    }
    return res;
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
};


TEST(ClaimTest, NholmannTest) {
  const auto claim = jwt::basic_claim<nlohmann::json::value_type, nlohmann::json::object_t, nlohmann::json::array_t,
                        std::string, double, int64_t, bool>(std::string("string"));

  std::string token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0."
      "WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
  auto decoded = jwt::decode<nlohmann::json::value_type, nlohmann::json::object_t, nlohmann::json::array_t,
                        std::string, double, int64_t, bool, nlohmann_traits>(token);

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
