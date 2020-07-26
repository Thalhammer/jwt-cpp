#include <jwt-cpp/jwt.h>

extern "C" {

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  jwt::decode(std::string{(char *)Data, Size});
  return 0; // Non-zero return values are reserved for future use.
}
}