#include <gtest/gtest.h>
#include "jwt-cpp/jwt.h"

namespace {
    extern std::string google_cert;
    extern std::string google_cert_base64_der;
    extern std::string google_cert_key;
}

TEST(HelperTest, Cert2Pubkey) {
    auto key = jwt::helper::extract_pubkey_from_cert(google_cert);
    ASSERT_EQ(google_cert_key, key);
}

TEST(HelperTest, Base64DER2PemCert) {
    auto cert_pem = jwt::helper::convert_base64_der_to_pem (google_cert_base64_der);
    ASSERT_EQ(google_cert, cert_pem);
}

TEST(HelperTest, ErrorCodeMessages) {
    ASSERT_EQ(std::error_code(jwt::error::rsa_error::ok).message(), "no error");
    ASSERT_EQ(std::error_code(static_cast<jwt::error::rsa_error>(-1)).message(), "unknown RSA error");
    ASSERT_EQ(std::error_code(jwt::error::rsa_error::ok).category().name(), std::string("rsa_error"));

    ASSERT_EQ(std::error_code(jwt::error::ecdsa_error::ok).message(), "no error");
    ASSERT_EQ(std::error_code(static_cast<jwt::error::ecdsa_error>(-1)).message(), "unknown ECDSA error");
    ASSERT_EQ(std::error_code(jwt::error::ecdsa_error::ok).category().name(), std::string("ecdsa_error"));

    ASSERT_EQ(std::error_code(jwt::error::signature_verification_error::ok).message(), "no error");
    ASSERT_EQ(std::error_code(static_cast<jwt::error::signature_verification_error>(-1)).message(), "unknown signature verification error");
    ASSERT_EQ(std::error_code(jwt::error::signature_verification_error::ok).category().name(), std::string("signature_verification_error"));

    ASSERT_EQ(std::error_code(jwt::error::signature_generation_error::ok).message(), "no error");
    ASSERT_EQ(std::error_code(static_cast<jwt::error::signature_generation_error>(-1)).message(), "unknown signature generation error");
    ASSERT_EQ(std::error_code(jwt::error::signature_generation_error::ok).category().name(), std::string("signature_generation_error"));

    ASSERT_EQ(std::error_code(jwt::error::token_verification_error::ok).message(), "no error");
    ASSERT_EQ(std::error_code(static_cast<jwt::error::token_verification_error>(-1)).message(), "unknown token verification error");
    ASSERT_EQ(std::error_code(jwt::error::token_verification_error::ok).category().name(), std::string("token_verification_error"));

    int i = 10;
    for(i = 10; i < 18; i++) {
        ASSERT_NE(std::error_code(static_cast<jwt::error::rsa_error>(i)).message(),
            std::error_code(static_cast<jwt::error::rsa_error>(-1)).message());
    }
    ASSERT_EQ(std::error_code(static_cast<jwt::error::rsa_error>(i)).message(),
        std::error_code(static_cast<jwt::error::rsa_error>(-1)).message());

    for(i = 10; i < 16; i++) {
        ASSERT_NE(std::error_code(static_cast<jwt::error::ecdsa_error>(i)).message(),
            std::error_code(static_cast<jwt::error::ecdsa_error>(-1)).message());
    }
    ASSERT_EQ(std::error_code(static_cast<jwt::error::ecdsa_error>(i)).message(),
        std::error_code(static_cast<jwt::error::ecdsa_error>(-1)).message());

    for(i = 10; i < 16; i++) {
        ASSERT_NE(std::error_code(static_cast<jwt::error::signature_verification_error>(i)).message(),
            std::error_code(static_cast<jwt::error::signature_verification_error>(-1)).message());
    }
    ASSERT_EQ(std::error_code(static_cast<jwt::error::signature_verification_error>(i)).message(),
        std::error_code(static_cast<jwt::error::signature_verification_error>(-1)).message());

    for(i = 10; i < 22; i++) {
        ASSERT_NE(std::error_code(static_cast<jwt::error::signature_generation_error>(i)).message(),
            std::error_code(static_cast<jwt::error::signature_generation_error>(-1)).message());
    }
    ASSERT_EQ(std::error_code(static_cast<jwt::error::signature_generation_error>(i)).message(),
        std::error_code(static_cast<jwt::error::signature_generation_error>(-1)).message());

    for(i = 10; i < 16; i++) {
        ASSERT_NE(std::error_code(static_cast<jwt::error::token_verification_error>(i)).message(),
            std::error_code(static_cast<jwt::error::token_verification_error>(-1)).message());
    }
    ASSERT_EQ(std::error_code(static_cast<jwt::error::token_verification_error>(i)).message(),
        std::error_code(static_cast<jwt::error::token_verification_error>(-1)).message());
}

namespace {
    std::string google_cert = R"(-----BEGIN CERTIFICATE-----
MIIF8DCCBVmgAwIBAgIKYFOB9QABAACIvTANBgkqhkiG9w0BAQUFADBGMQswCQYD
VQQGEwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzEiMCAGA1UEAxMZR29vZ2xlIElu
dGVybmV0IEF1dGhvcml0eTAeFw0xMzA1MjIxNTQ5MDRaFw0xMzEwMzEyMzU5NTla
MGYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1N
b3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMRUwEwYDVQQDFAwqLmdv
b2dsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARmSpIUbCqhUBq1UwnR
Ai7/TNSk6W8JmasR+I0r/NLDYv5yApbAz8HXXN8hDdurMRP6Jy1Q0UIKmyls8HPH
exoCo4IECjCCBAYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAsGA1Ud
DwQEAwIHgDAdBgNVHQ4EFgQUU3jT0NVNRgU5ZinRHGrlyoGEnoYwHwYDVR0jBBgw
FoAUv8Aw6/VDET5nup6R+/xq2uNrEiQwWwYDVR0fBFQwUjBQoE6gTIZKaHR0cDov
L3d3dy5nc3RhdGljLmNvbS9Hb29nbGVJbnRlcm5ldEF1dGhvcml0eS9Hb29nbGVJ
bnRlcm5ldEF1dGhvcml0eS5jcmwwZgYIKwYBBQUHAQEEWjBYMFYGCCsGAQUFBzAC
hkpodHRwOi8vd3d3LmdzdGF0aWMuY29tL0dvb2dsZUludGVybmV0QXV0aG9yaXR5
L0dvb2dsZUludGVybmV0QXV0aG9yaXR5LmNydDAMBgNVHRMBAf8EAjAAMIICwwYD
VR0RBIICujCCAraCDCouZ29vZ2xlLmNvbYINKi5hbmRyb2lkLmNvbYIWKi5hcHBl
bmdpbmUuZ29vZ2xlLmNvbYISKi5jbG91ZC5nb29nbGUuY29tghYqLmdvb2dsZS1h
bmFseXRpY3MuY29tggsqLmdvb2dsZS5jYYILKi5nb29nbGUuY2yCDiouZ29vZ2xl
LmNvLmlugg4qLmdvb2dsZS5jby5qcIIOKi5nb29nbGUuY28udWuCDyouZ29vZ2xl
LmNvbS5hcoIPKi5nb29nbGUuY29tLmF1gg8qLmdvb2dsZS5jb20uYnKCDyouZ29v
Z2xlLmNvbS5jb4IPKi5nb29nbGUuY29tLm14gg8qLmdvb2dsZS5jb20udHKCDyou
Z29vZ2xlLmNvbS52boILKi5nb29nbGUuZGWCCyouZ29vZ2xlLmVzggsqLmdvb2ds
ZS5mcoILKi5nb29nbGUuaHWCCyouZ29vZ2xlLml0ggsqLmdvb2dsZS5ubIILKi5n
b29nbGUucGyCCyouZ29vZ2xlLnB0gg8qLmdvb2dsZWFwaXMuY26CFCouZ29vZ2xl
Y29tbWVyY2UuY29tgg0qLmdzdGF0aWMuY29tggwqLnVyY2hpbi5jb22CECoudXJs
Lmdvb2dsZS5jb22CFioueW91dHViZS1ub2Nvb2tpZS5jb22CDSoueW91dHViZS5j
b22CFioueW91dHViZWVkdWNhdGlvbi5jb22CCyoueXRpbWcuY29tggthbmRyb2lk
LmNvbYIEZy5jb4IGZ29vLmdsghRnb29nbGUtYW5hbHl0aWNzLmNvbYIKZ29vZ2xl
LmNvbYISZ29vZ2xlY29tbWVyY2UuY29tggp1cmNoaW4uY29tggh5b3V0dS5iZYIL
eW91dHViZS5jb22CFHlvdXR1YmVlZHVjYXRpb24uY29tMA0GCSqGSIb3DQEBBQUA
A4GBAAMn0K3j3yhC+X+uyh6eABa2Eq7xiY5/mUB886Ir19vxluSMNKD6n/iY8vHj
trn0BhuW8/vmJyudFkIcEDUYE4ivQMlsfIL7SOGw6OevVLmm02aiRHWj5T20Ds+S
OpueYUG3NBcHP/5IzhUYIQJbGzlQaUaZBMaQeC8ZslMNLWI2
-----END CERTIFICATE-----
)";

    std::string google_cert_base64_der =
        "MIIF8DCCBVmgAwIBAgIKYFOB9QABAACIvTANBgkqhkiG9w0BAQUFADBGMQswCQYD"
        "VQQGEwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzEiMCAGA1UEAxMZR29vZ2xlIElu"
        "dGVybmV0IEF1dGhvcml0eTAeFw0xMzA1MjIxNTQ5MDRaFw0xMzEwMzEyMzU5NTla"
        "MGYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1N"
        "b3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMRUwEwYDVQQDFAwqLmdv"
        "b2dsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARmSpIUbCqhUBq1UwnR"
        "Ai7/TNSk6W8JmasR+I0r/NLDYv5yApbAz8HXXN8hDdurMRP6Jy1Q0UIKmyls8HPH"
        "exoCo4IECjCCBAYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAsGA1Ud"
        "DwQEAwIHgDAdBgNVHQ4EFgQUU3jT0NVNRgU5ZinRHGrlyoGEnoYwHwYDVR0jBBgw"
        "FoAUv8Aw6/VDET5nup6R+/xq2uNrEiQwWwYDVR0fBFQwUjBQoE6gTIZKaHR0cDov"
        "L3d3dy5nc3RhdGljLmNvbS9Hb29nbGVJbnRlcm5ldEF1dGhvcml0eS9Hb29nbGVJ"
        "bnRlcm5ldEF1dGhvcml0eS5jcmwwZgYIKwYBBQUHAQEEWjBYMFYGCCsGAQUFBzAC"
        "hkpodHRwOi8vd3d3LmdzdGF0aWMuY29tL0dvb2dsZUludGVybmV0QXV0aG9yaXR5"
        "L0dvb2dsZUludGVybmV0QXV0aG9yaXR5LmNydDAMBgNVHRMBAf8EAjAAMIICwwYD"
        "VR0RBIICujCCAraCDCouZ29vZ2xlLmNvbYINKi5hbmRyb2lkLmNvbYIWKi5hcHBl"
        "bmdpbmUuZ29vZ2xlLmNvbYISKi5jbG91ZC5nb29nbGUuY29tghYqLmdvb2dsZS1h"
        "bmFseXRpY3MuY29tggsqLmdvb2dsZS5jYYILKi5nb29nbGUuY2yCDiouZ29vZ2xl"
        "LmNvLmlugg4qLmdvb2dsZS5jby5qcIIOKi5nb29nbGUuY28udWuCDyouZ29vZ2xl"
        "LmNvbS5hcoIPKi5nb29nbGUuY29tLmF1gg8qLmdvb2dsZS5jb20uYnKCDyouZ29v"
        "Z2xlLmNvbS5jb4IPKi5nb29nbGUuY29tLm14gg8qLmdvb2dsZS5jb20udHKCDyou"
        "Z29vZ2xlLmNvbS52boILKi5nb29nbGUuZGWCCyouZ29vZ2xlLmVzggsqLmdvb2ds"
        "ZS5mcoILKi5nb29nbGUuaHWCCyouZ29vZ2xlLml0ggsqLmdvb2dsZS5ubIILKi5n"
        "b29nbGUucGyCCyouZ29vZ2xlLnB0gg8qLmdvb2dsZWFwaXMuY26CFCouZ29vZ2xl"
        "Y29tbWVyY2UuY29tgg0qLmdzdGF0aWMuY29tggwqLnVyY2hpbi5jb22CECoudXJs"
        "Lmdvb2dsZS5jb22CFioueW91dHViZS1ub2Nvb2tpZS5jb22CDSoueW91dHViZS5j"
        "b22CFioueW91dHViZWVkdWNhdGlvbi5jb22CCyoueXRpbWcuY29tggthbmRyb2lk"
        "LmNvbYIEZy5jb4IGZ29vLmdsghRnb29nbGUtYW5hbHl0aWNzLmNvbYIKZ29vZ2xl"
        "LmNvbYISZ29vZ2xlY29tbWVyY2UuY29tggp1cmNoaW4uY29tggh5b3V0dS5iZYIL"
        "eW91dHViZS5jb22CFHlvdXR1YmVlZHVjYXRpb24uY29tMA0GCSqGSIb3DQEBBQUA"
        "A4GBAAMn0K3j3yhC+X+uyh6eABa2Eq7xiY5/mUB886Ir19vxluSMNKD6n/iY8vHj"
        "trn0BhuW8/vmJyudFkIcEDUYE4ivQMlsfIL7SOGw6OevVLmm02aiRHWj5T20Ds+S"
        "OpueYUG3NBcHP/5IzhUYIQJbGzlQaUaZBMaQeC8ZslMNLWI2";

    std::string google_cert_key = R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZkqSFGwqoVAatVMJ0QIu/0zUpOlv
CZmrEfiNK/zSw2L+cgKWwM/B11zfIQ3bqzET+ictUNFCCpspbPBzx3saAg==
-----END PUBLIC KEY-----
)";
}
