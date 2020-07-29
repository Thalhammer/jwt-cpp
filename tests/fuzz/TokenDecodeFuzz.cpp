#include <jwt-cpp/jwt.h>

extern "C" {

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  
  
    try
    {
        // step 1: parse input
        const auto jwt1 = jwt::decode(std::string{(char *)Data, Size});

        try
        {
            // step 2: round trip
            std::string s1 = jwt1.get_token();
            const auto jwt2 = jwt::decode(s1);

            // claims must match
            assert(jwt1.get_header_claims() == jwt2.get_header_claims());
            assert(jwt1.get_payload_claims() == jwt2.get_payload_claims());
        }
        catch (...)
        {
            // parsing raw data twice must not fail
            assert(false);
        }
    }
    catch (...)
    {
        // parse errors are ok, because input may be random bytes
    }
  
  return 0; // Non-zero return values are reserved for future use.
}
}
