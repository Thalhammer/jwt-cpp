#include <iostream>
#include <jwt-cpp/jwt.h>

#include <openssl/rand.h>

std::string write_bio_to_string(std::unique_ptr<BIO, decltype(&BIO_free_all)>& bio_out) {
	char* ptr = nullptr;
	auto len = BIO_get_mem_data(bio_out.get(), &ptr);
	if (len <= 0 || ptr == nullptr) { throw std::exception(); }
	return {ptr, static_cast<size_t>(len)};
}

int main() {
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_generate(pctx, &pkey);
	std::string pem_public_key = [&]() {
		auto bio_out = jwt::helper::make_mem_buf_bio();
		PEM_write_bio_PUBKEY(bio_out.get(), pkey);

		const auto pub_key = write_bio_to_string(bio_out);
		std::cout << pub_key << std::endl;
		return pub_key;
	}();

	// https://stackoverflow.com/questions/69179822/jwk-key-creation-with-x5c-and-x5t-parameters
	// https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl
	std::unique_ptr<X509, decltype(&X509_free)> cert{X509_new(), X509_free};

	ASN1_INTEGER* serial_number = X509_get_serialNumber(cert.get());
	ASN1_INTEGER_set(serial_number, 1); // serial number

	X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);					  // now
	X509_gmtime_adj(X509_get_notAfter(cert.get()), 10 * 365 * 24 * 3600); // accepts secs

	X509_set_pubkey(cert.get(), pkey);
	X509_NAME* name = X509_get_subject_name(cert.get());

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"JWT-CPP", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"localhost", -1, -1, 0);

	X509_set_issuer_name(cert.get(), name);
	X509_sign(cert.get(), pkey, EVP_sha256()); // some hash type here

	std::string base64_x5c = [&]() {
		// PEM_write_bio_X509(certFile.get(), cert.get());
		// PEM_write_bio_PrivateKey(keyFile.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr);
		auto bio_out = jwt::helper::make_mem_buf_bio();
		i2d_X509_bio(bio_out.get(), cert.get());

		const auto der_cert = write_bio_to_string(bio_out);
		const auto b64_der_cert = jwt::base::encode<jwt::alphabet::base64>(der_cert);
		std::cout << b64_der_cert << std::endl;
		return b64_der_cert;
	}();

	// https://stackoverflow.com/questions/8135209/open-ssl-certificate-fingerprint-in-c

	// std::string base64_x5c = [&](){
	// 	auto bio_out = jwt::helper::make_mem_buf_bio();
	// 	i2d_PUBKEY_bio(bio_out.get(), pkey);

	// 	const auto der_pub_key = write_bio_to_string(bio_out);
	// 	const auto x5c = jwt::base::encode<jwt::alphabet::base64>(der_pub_key);
	// 	std::cout << x5c << std::endl;
	// 	return x5c;
	// }();

	std::string pem_priv_key = [&]() {
		auto bio_out = jwt::helper::make_mem_buf_bio();
		PEM_write_bio_PrivateKey(bio_out.get(), pkey, NULL, NULL, 0, 0, (void*)"");

		const auto priv_key = write_bio_to_string(bio_out);
		std::cout << priv_key << std::endl;
		return priv_key;
	}();

	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(pkey);

#if defined(JWT_OPENSSL_3_0)
	BIGNUM* n = nullptr;
	EVP_PKEY_get_bn_param(pkey, "n", &n);
	BIGNUM* e = nullptr;
	EVP_PKEY_get_bn_param(pkey, "e", &e);
#else
	EVP_PKEY_get_bn_param RSA* rsa = EVP_PKEY_get1_RSA(pkey);
	const BIGNUM* n = RSA_get0_n(rsa);
	const BIGNUM* e = RSA_get0_e(rsa);
#endif

	const auto modulus =
		jwt::base::trim<jwt::alphabet::base64url>(jwt::base::encode<jwt::alphabet::base64url>(jwt::helper::bn2raw(n)));
	const auto exp =
		jwt::base::trim<jwt::alphabet::base64url>(jwt::base::encode<jwt::alphabet::base64url>(jwt::helper::bn2raw(e)));

#if defined(JWT_OPENSSL_3_0)
	BN_free(n);
	BN_free(e);
#endif

	std::cout << modulus << std::endl;
	std::cout << exp << std::endl;

	// https://stackoverflow.com/a/30138974
	unsigned char nonce[24];
	RAND_bytes(nonce, sizeof(nonce));
	std::string jti = jwt::base::encode<jwt::alphabet::base64url>(std::string{(const char*)nonce, sizeof(nonce)});

	std::string raw_jwks =
		R"({"keys": [{
		"kid":"internal-gateway-jwt.api.sc.net",
		"alg": "RS256",
    "kty": "RSA",
    "use": "sig",
    "x5c": [
      ")" +
		base64_x5c + R"("
    ],
    "n": ")" +
		modulus + R"(",
    "e": "AQAB"
	},
{
		"kid":"internal-123456",
		"use":"sig",
		"x5c":["MIIG1TCCBL2gAwIBAgIIFvMVGp6t\/cMwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCR0IxIDAeBgNVBAoMF1N0YW5kYXJkIENoYXJ0ZXJlZCBCYW5rMTUwMwYDVQQDDCxTdGFuZGFyZCBDaGFydGVyZWQgQmFuayBTaWduaW5nIENBIEcxIC0gU0hBMjAeFw0xODEwMTAxMTI2MzVaFw0yMjEwMTAxMTI2MzVaMIG9MQswCQYDVQQGEwJTRzESMBAGA1UECAwJU2luZ2Fwb3JlMRIwEAYDVQQHDAlTaW5nYXBvcmUxIDAeBgNVBAoMF1N0YW5kYXJkIENoYXJ0ZXJlZCBCYW5rMRwwGgYDVQQLDBNGb3VuZGF0aW9uIFNlcnZpY2VzMSgwJgYDVQQDDB9pbnRlcm5hbC1nYXRld2F5LWp3dC5hcGkuc2MubmV0MRwwGgYJKoZIhvcNAQkBFg1BUElQU1NAc2MuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArVWBoIi3IJ4nOWXu7\/SDxczqMou1B+c4c2FdQrOXrK31HxAaz4WEtma9BLXFdFHJ5mCCPIvdUcVxxnCynqhMOkZ\/a7acQbUD9cDzI8isMB9JL7VooDw0CctxHxffjqQQVIEhC2Q7zsM1pQayR7cl+pbBlvHIoRxq2n1B0fFvfoiosjf4kDiCpgHdM+v5Hw9aVYmUbroHxmQWqhB0iRTJQPPLZqqQVC50A1Q\/96gkwoODyotc46Uy9wYEpdGrtDG\/thWay3fmMsjpWR0U25xFIrxTrfCGBblYpD7juukWWml2E9rtE2rHgUxbymxXjEw7xrMwcGrhOGyqwoBqJy1JVwIDAQABo4ICLTCCAikwZAYIKwYBBQUHAQEEWDBWMFQGCCsGAQUFBzABhkhodHRwOi8vY29yZW9jc3AuZ2xvYmFsLnN0YW5kYXJkY2hhcnRlcmVkLmNvbS9lamJjYS9wdWJsaWN3ZWIvc3RhdHVzL29jc3AwHQYDVR0OBBYEFIinW4BNDeVEFcuLf8YjZjtySoW9MAwGA1UdEwEB\/wQCMAAwHwYDVR0jBBgwFoAUfNZMoZi33nKrcmVU3TFVQnuEi\/4wggFCBgNVHR8EggE5MIIBNTCCATGggcKggb+GgbxodHRwOi8vY29yZWNybC5nbG9iYWwuc3RhbmRhcmRjaGFydGVyZWQuY29tL2VqYmNhL3B1YmxpY3dlYi93ZWJkaXN0L2NlcnRkaXN0P2NtZD1jcmwmaXNzdWVyPUNOPVN0YW5kYXJkJTIwQ2hhcnRlcmVkJTIwQmFuayUyMFNpZ25pbmclMjBDQSUyMEcxJTIwLSUyMFNIQTIsTz1TdGFuZGFyZCUyMENoYXJ0ZXJlZCUyMEJhbmssQz1HQqJqpGgwZjE1MDMGA1UEAwwsU3RhbmRhcmQgQ2hhcnRlcmVkIEJhbmsgU2lnbmluZyBDQSBHMSAtIFNIQTIxIDAeBgNVBAoMF1N0YW5kYXJkIENoYXJ0ZXJlZCBCYW5rMQswCQYDVQQGEwJHQjAOBgNVHQ8BAf8EBAMCBsAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQBtsoRlDHuOTDChcWdfdVUtRgP0U0ijDSeJi8vULN1rgYnqqJc4PdJno50aiu9MGlxY02O7HW7ZVD6QEG\/pqHmZ0sbWpb\/fumMgZSjP65IcGuS53zgcNtLYnyXyEv+v5T\/CK3bk4Li6tUW3ScJPUwVWwP1E0\/u6aBSb5k\/h4lTwS1o88ybS5pJOg6XutXByp991QQrrs7tp7fKNynjNZbFuG3J1e09X+zTfJOpjaDUofQTkt8IyMRI6Cs4wI1eZA+dAIL8B0n8ze1mRl1FOJqgdZrAQjoqZkCTnc0Il5VY\/dUXxGVg6D9e5pfck3FWT107K9\/5EZoxytpqYXFCjMXi5hx4YjK17OUgm82mZhvqkNdzF8Yq2vFuB3LPfyelESq99xFLykvinrVm1NtZKeDTT1Jq\/VvZt6stO\/tovq1RfJJcznpYcwOzxlnhGR6E+hxuBx7aDJzGf0JaoRxQILH1B2XV9WDI3HPYQsP7XtriX+QUJ\/aly28QkV48RmaGYCsly43YZu1MKudSsw+dhnbZzRsg\/aes3dzGW2x137bQPtux7k2LCSpsTXgedhOys28YoGlsoe8kUv0myAU4Stt+I3mrwO3BKUn+tJggvlDiiiyT1tg2HiklyU\/2FxQkZRMeB0eRrXTpg3l9x2mpF+dDFxOMKszxwD2kgoEZgo6o58A=="],
		"n":"nr9UsxnPVd21iuiGcIJ_Qli2XVlAZe5VbELA1hO2-L4k5gI4fjHZ3ysUcautLpbOYogOQgsnlpsLrCmvNDvBDVzVp2nMbpguJlt12vHSP1fRJJpipGQ8qU-VaXsC4OjOQf3H9ojAU5Vfnl5gZ7kVCd8g4M29l-IRyNpxE-Ccxc2Y7molsCHT6GHLMMBVsd11JIOXMICJf4hz2YYkQ1t7C8SaB2RFRPuGO5Mn6mfAnwdmRera4TBz6_pIPPCgCbN8KOdJItWkr9F7Tjv_0nhh-ZVlQvbQ9PXHyKTj00g3IYUlbZIWHm0Ley__fzNZk2dyAAVjNA2QSzTZJc33MQx1pQ",
		"e":"AQAB",
		"x5t":"-qC0akuyiHTV5aFsKVWM9da7lzq6DLrj09I",
		"alg":"RS256",
		"kty":"RSA"
	}
]})";

	std::string token = jwt::create()
							.set_issuer("auth0")
							.set_type("JWT")
							.set_id(jti)
							.set_key_id("internal-gateway-jwt.api.sc.net")
							.set_subject("jwt-cpp.example.localhost")
							.set_issued_at(std::chrono::system_clock::now())
							.set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{36000})
							.set_payload_claim("sample", jwt::claim(std::string{"test"}))
							.sign(jwt::algorithm::rs256("", pem_priv_key, "", ""));

	std::cout << token << std::endl;

	auto decoded_jwt = jwt::decode(token);
	auto jwks = jwt::parse_jwks(raw_jwks);
	auto jwk = jwks.get_jwk(decoded_jwt.get_key_id());

	auto issuer = decoded_jwt.get_issuer();
	auto x5c = jwk.get_x5c_key_value();

	if (!x5c.empty() && !issuer.empty()) {
		auto verifier =
			jwt::verify()
				.allow_algorithm(jwt::algorithm::rs256(jwt::helper::convert_base64_der_to_pem(x5c), "", "", ""))
				.with_issuer(issuer)
				.leeway(60UL); // value in seconds, add some to compensate timeout

		verifier.verify(decoded_jwt);
	}
	// else if the optional 'x5c' was not present
	{
		const auto modulus = jwk.get_jwk_claim("n").as_string();
		const auto exponent = jwk.get_jwk_claim("e").as_string();
		auto verifier = jwt::verify()
							.allow_algorithm(jwt::algorithm::rs256(
								jwt::helper::create_public_key_from_rsa_components(modulus, exponent)))
							.with_issuer(issuer)
							.leeway(60UL); // value in seconds, add some to compensate timeout

		verifier.verify(decoded_jwt);
	}
}
