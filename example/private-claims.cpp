#include <jwt-cpp/jwt.h>

#include <iostream>
#include <sstream>

using sec = std::chrono::seconds;
using min = std::chrono::minutes;

int main(int argc, const char **argv) {
  jwt::claim from_raw_json;
  std::istringstream iss{R"##({"api":{"array":[1,2,3],"null":null}})##"};
  iss >> from_raw_json;

  jwt::claim::set_t list{"once", "twice"};

  std::vector<int64_t> big_numbers{727663072ull, 770979831ull, 427239169ull,
                                   525936436ull};

  const auto time = jwt::date::clock::now();
  const auto token =
      jwt::create()
          .set_type("JWT")
          .set_issuer("auth.mydomain.io")
          .set_audience("mydomain.io")
          .set_issued_at(time)
          .set_not_before(time + sec{15})
          .set_expires_at(time + sec{15} + min{2})
          .set_payload_claim("boolean", picojson::value(true))
          .set_payload_claim("integer", picojson::value(int64_t{12345}))
          .set_payload_claim("precision", picojson::value(12.345))
          .set_payload_claim("strings", jwt::claim(list))
          .set_payload_claim("array",
                             jwt::claim(big_numbers.begin(), big_numbers.end()))
          .set_payload_claim("object", from_raw_json)
          .sign(jwt::algorithm::none{});

  auto decoded = jwt::decode(token);

  for (auto &e : decoded.get_payload_claims())
    std::cout << e.first << " = " << e.second << std::endl;

  const auto api_array =
      decoded.get_payload_claims()["object"].to_json().get("api").get("array");
  std::cout << "api array = " << api_array << std::endl;
}