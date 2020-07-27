#include <jwt-cpp/base.h>
#include <openssl/evp.h>
#include <vector>

extern "C" {

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  std::vector<uint8_t> encoded(4*((Size+2)/3)+1, 0);

  EVP_EncodeBlock(encoded.data(), Data, Size);
  // if(EVP_EncodeBlock(encoded.data(), Data, Size) != encoded.size())
    //abort(); // Critical error using OpenSSL
                               
  jwt::base::decode<jwt::alphabet::base64>(std::string{encoded.begin(), encoded.end() - 1}); // TO DO: Compare against input
  return 0; // Non-zero return values are reserved for future use.
}

}
