#include <jwt-cpp/jwt.h>

extern "C" {

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  const auto data = std::string{(char *)Data, Size};
  jwt::create().set_id(data).sign(
    jwt::algorithm::none{}
  );
  return 0; // Non-zero return values are reserved for future use.
}
}