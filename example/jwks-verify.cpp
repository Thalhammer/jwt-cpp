#include <iostream>
#include <jwt-cpp/jwt.h>

int main() {
	std::string raw_jwks =
		R"({"keys": [{
		"kid":"internal-gateway-jwt.api.sc.net",
		"alg": "RS256",
    "kty": "RSA",
    "use": "sig",
    "x5c": [
      "MIIE2jCCAsICAQEwDQYJKoZIhvcNAQELBQAwMzELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0pXVC1DUFAxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yMzEyMjIxMzIzNTdaFw0zMzEyMTkxMzIzNTdaMDMxCzAJBgNVBAYTAlVTMRAwDgYDVQQKDAdKV1QtQ1BQMRIwEAYDVQQDDAlsb2NhbGhvc3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDl0gyL9KCpoXsJlvBaBUsJTAgvFhbgsBjpxT6m2xv0fgtGDBwgaiPvuMnClTU/kYkKb8c1GTkMedKp9YcM57HWTk9yqGTy6QBnMMxbAJYNwWQ4Dbr4qKSC6C3KzYws/Bqyv8OC9NAOyqJbtdp4iObRjyaet+PLTXywuu02xtyRg3B+1aAONgUVDyS5u57NSD4rEZ+rw30Ne1doSClWmMDqEd72y8cjx3eAqn0HcAxSQ6MNMmNk7/M8FQD3DTM1Ef0G5oHyJIw7WmY+gxuD8386r/CkswINzadMwObPlTSdAN8BRzedtrqgb+D/K4pi2zhCiuIVujFX6M/hsGvj7g2M9E9MR8iEuHWCY9frQKIR+JTH3D1snoJp60qKoa51qBznsEr9RP2utGniPCq3+JY+ZX0JK8vl5tiSZpy6N0yRbRmY3XLdA5fKRzhcsB3eUrmTtr9ywjZX7Ll6QMvUyicubGTojhqJFQbvuvvops9PoCMXFE3x6cJ2QhPoi8+BvUdYisrtjDFe+YgrgQvPMa/CpOpDJJDEs2SVRcauCZOUdqLCwZylNuW0CgIjWP8l99P7l1zGeT8VJPhmABYyPM+RtNYDamAlUOCqRqgz/gPjEeMeulQTvH1lAqATAAX1oftlq6o4VoqROs2M3eAXqPhvsLBeTmCob+5ca887MkcP6wIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQBW2kREK4hlzxCDqykxrwfbQpiPwrbFmn+3RDJla+pI4L3wrvYT1nU96guFIU3zKnbMzqwPMRUCUjadr2jKxAmMWxCd/ThHQB+ne5xTvx7/6RVQfGjyMCG/SZtSH8/aO7ILNRtPT+SL5ZZwezaqv6gD89tSXB/w/0pYXy70wDuU17KCrTsKSISWGJ1cKi5l2R/m/ZaGjcV8U8NcFepF2bX3u/i0zhaqOqjiwrSEt7fWGDLabPs6n7GtfibZROEDZ/h0JrDINC+6mSfTOYAMJvGjeHA3H/NvzqR+CJgpXGCqElqVuBF0HdxPmwRRBoZC/BLIEcz0VHmB4rcpfaV47TZT+J+04fHYp4Y1S0u112CDrDe+61cDrnbDHC7aGX0G93pYSBKAB1e3LLc9rXQgf2F0pRtFB3rgZA9MtJ+TL7DUvY4VXJNq3v7UolIdldYRdk21YqAS2Hp0fivvFoEk2P/WbwDEErxR0FkZ/JQoI9FMJ9AvDxa4MsFFtlQVInfD2HUu+nhnuEAA8R6L+F2XqhfLY/H7H31iFBK6UCuqptED71VwWHqfBsAPRhLXAqGco7Ln2dzioyj0QdwJqQQIqigltSYtXxfIMLW0BekQ5yln7QTxnZlobkPHUW9s3NK+OMLuKCzVREzjic/aioQP3cRBMXkG2deMwrk3aX8yJuz4gA=="
    ],
    "n": "5dIMi_SgqaF7CZbwWgVLCUwILxYW4LAY6cU-ptsb9H4LRgwcIGoj77jJwpU1P5GJCm_HNRk5DHnSqfWHDOex1k5Pcqhk8ukAZzDMWwCWDcFkOA26-Kikgugtys2MLPwasr_DgvTQDsqiW7XaeIjm0Y8mnrfjy018sLrtNsbckYNwftWgDjYFFQ8kubuezUg-KxGfq8N9DXtXaEgpVpjA6hHe9svHI8d3gKp9B3AMUkOjDTJjZO_zPBUA9w0zNRH9BuaB8iSMO1pmPoMbg_N_Oq_wpLMCDc2nTMDmz5U0nQDfAUc3nba6oG_g_yuKYts4QoriFboxV-jP4bBr4-4NjPRPTEfIhLh1gmPX60CiEfiUx9w9bJ6CaetKiqGudagc57BK_UT9rrRp4jwqt_iWPmV9CSvL5ebYkmacujdMkW0ZmN1y3QOXykc4XLAd3lK5k7a_csI2V-y5ekDL1MonLmxk6I4aiRUG77r76KbPT6AjFxRN8enCdkIT6IvPgb1HWIrK7YwxXvmIK4ELzzGvwqTqQySQxLNklUXGrgmTlHaiwsGcpTbltAoCI1j_JffT-5dcxnk_FST4ZgAWMjzPkbTWA2pgJVDgqkaoM_4D4xHjHrpUE7x9ZQKgEwAF9aH7ZauqOFaKkTrNjN3gF6j4b7CwXk5gqG_uXGvPOzJHD-s",
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

	std::string token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImludGVybmFsLWdhdGV3YXktand0LmFwaS5zYy5uZXQiLCJ0eXAiOiJKV1QifQ."
						"eyJleHAiOjE3MDMyODc0MzcsImlhdCI6MTcwMzI1MTQzNywiaXNzIjoiYXV0aDAiLCJqdGkiOiJ6dENUQnAyT2tWZU9CaU"
						"FMR1diU3NRQ3d2bVJBQTlzeiIsInNhbXBsZSI6InRlc3QiLCJzdWIiOiJqd3QtY3BwLmV4YW1wbGUubG9jYWxob3N0In0."
						"lsouv8rqvzcRP869v-iAQlqmsJ9gHIUrm2uyFVEv_Dc_Cvkm4qHSK5s8RCMD9ilIzXMXOjViOUV3lEIOPcjVCR0TOS8w4_"
						"rVf78P0Dx-sPKjpXGg5NYWvl6wduAttYq6CYE-oXZZRkbQoLyH8zWB6PQO7bBbMz8z5BT86dxtulcI8F3j0lHY6IAemKH_"
						"wK8LXVvwt8JctUuhlDMPEZ969pIvJHdQAA_iaGFTqvpnDFSIIzH0hjPrv12pLTXm57guqEQZRDfDW3HVjt-rAKi_"
						"CJvEgdV98bo3ku9W0uv4kLmhJjIMepuZvoGMGQdF8UuJPfAYDZ-fnHPocS_"
						"hrurBu176y3qq9QeU9MlORZyjXx3BB4uAusFMUtzw5ON12gudzHzkVeimAaKO1AlXc1HiRXw2EdDeK6DVMQdgRWP16jVNY"
						"TF6iUEa824VltN0ObTw2wRuiGKMPGswdsSUyzw6UF9eHUL2ndSmTIjBL9BOJqCBTC3uD01jeIop3JMhKk0reL_-"
						"8AiCb3nunt1pIIZ13z1kOfg3BoS4pMgAmAxopSU4YY7vh0UK52IZCPxxntpVfY_8OQ54mVY1mqiht1aMe8L_"
						"Nmil1TuYi8RWBER1VypJF0uCbHTTrJ0nU61h5XjCz8b28YB2_x0t88dGHtx4s95L-quDLUdF2_BIMzHJhnw";

	auto decoded_jwt = jwt::decode(token);
	auto jwks = jwt::parse_jwks(raw_jwks);
	auto jwk = jwks.get_jwk(decoded_jwt.get_key_id());

	auto issuer = decoded_jwt.get_issuer();
	auto x5c = jwk.get_x5c_key_value();

	if (!x5c.empty() && !issuer.empty()) {
		std::cout << "Verifying with 'x5c' key" << std::endl;
		auto verifier =
			jwt::verify()
				.allow_algorithm(jwt::algorithm::rs256(jwt::helper::convert_base64_der_to_pem(x5c), "", "", ""))
				.with_issuer(issuer)
				.leeway(60UL); // value in seconds, add some to compensate timeout

		verifier.verify(decoded_jwt);
	}
	// else if the optional 'x5c' was not present
	{
		std::cout << "Verifying with RSA components" << std::endl;
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
