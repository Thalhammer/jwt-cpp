#include "jwt-cpp/jwt.h"
#include "nlohmann/json.hpp"
#include <gtest/gtest.h>

struct nlohmann_traits
    : jwt::json::traits<nlohmann::json, nlohmann::json, nlohmann::json,
                        std::string, double, int64_t, bool> {
  using json = nlohmann::json;

  static jwt::json::type get_type(const traits::value &val) {
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

  static traits::object as_object(const traits::value &val) {
    if (val.type() != json::value_t::object)
      throw std::bad_cast();
    return val.get<traits::object>();
  }

  static traits::string as_string(const traits::value &val) {
    if (val.type() != json::value_t::string)
      throw std::bad_cast();
    return val.get<traits::string>();
  }

  static traits::array as_array(const traits::value &val) {
    if (val.type() != json::value_t::array)
      throw std::bad_cast();
    return val.get<traits::array>();
  }

  static std::set<traits::string> as_set(const traits::value &val) {
    std::set<traits::string> res;
    for (auto &e : as_array(val)) {
      if (val.type() != json::value_t::string)
        throw std::bad_cast();
      res.insert(e.get<traits::string>());
    }
    return res;
  }

  static traits::integer as_int(const traits::value &val) {
    if (val.type() != json::value_t::number_integer)
      throw std::bad_cast();
    return val.get<traits::integer>();
  }

  static traits::boolean as_bool(const traits::value &val) {
    if (val.type() != json::value_t::boolean)
      throw std::bad_cast();
    return val.get<traits::boolean>();
  }

  static traits::number as_number(const traits::value &val) {
    if (val.type() != json::value_t::number_float)
      throw std::bad_cast();
    return val.get<traits::number>();
  }

  static bool parse(traits::value &val, traits::string str) {
    val = json::parse(str.begin(), str.end());
    return true;
  }
};

TEST(ClaimTest, NholmannTest) {
  std::string token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0In0."
      "WZnM3SIiSRHsbO3O7Z2bmIzTJ4EC32HRBKfLznHhrh4";
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
