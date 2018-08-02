#pragma once
#define PICOJSON_USE_INT64
#include "picojson.h"
#include "base.h"
#include <set>
#include <chrono>
#include <unordered_map>
#include <memory>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>

//If openssl version less than 1.1
#if OPENSSL_VERSION_NUMBER < 269484032
#define OPENSSL10
#endif

namespace jwt {
	using date = std::chrono::system_clock::time_point;

	struct signature_verification_exception : public std::runtime_error {
		signature_verification_exception()
			: std::runtime_error("signature verification failed")
		{}
		signature_verification_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		signature_verification_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct signature_generation_exception : public std::runtime_error {
		signature_generation_exception()
			: std::runtime_error("signature generation failed")
		{}
		signature_generation_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		signature_generation_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct rsa_exception : public std::runtime_error {
		rsa_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		rsa_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct ecdsa_exception : public std::runtime_error {
		ecdsa_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		ecdsa_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct token_verification_exception : public std::runtime_error {
		token_verification_exception()
			: std::runtime_error("token verification failed")
		{}
		token_verification_exception(const std::string& msg)
			: std::runtime_error("token verification failed: " + msg)
		{}
	};

	namespace algorithm {

		struct none {
			std::string sign(const std::string&) const {
				return "";
			}
			void verify(const std::string&, const std::string& signature) const {
				if (!signature.empty())
					throw signature_verification_exception();
			}
			std::string name() const {
				return "none";
			}
		};
		struct hmacsha {
			hmacsha(std::string key, const EVP_MD*(*md)(), const std::string& name)
				: secret(std::move(key)), md(md), alg_name(name)
			{}
			std::string sign(const std::string& data) const {
				std::string res;
				res.resize(EVP_MAX_MD_SIZE);
				unsigned int len = res.size();
				if (HMAC(md(), secret.data(), secret.size(), (const unsigned char*)data.data(), data.size(), (unsigned char*)res.data(), &len) == nullptr)
					throw signature_generation_exception();
				res.resize(len);
				return res;
			}
			void verify(const std::string& data, const std::string& signature) const {
				try {
					auto res = sign(data);
					bool matched = true;
					for (size_t i = 0; i < std::min<size_t>(res.size(), signature.size()); i++)
						if (res[i] != signature[i])
							matched = false;
					if (res.size() != signature.size())
						matched = false;
					if (!matched)
						throw signature_verification_exception();
				}
				catch (const signature_generation_exception&) {
					throw signature_verification_exception();
				}
			}
			std::string name() const {
				return alg_name;
			}
		private:
			const std::string secret;
			const EVP_MD*(*md)();
			const std::string alg_name;
		};
		struct rsa {
			rsa(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), const std::string& name)
				: md(md), alg_name(name)
			{
				std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
				if ((size_t)BIO_write(pubkey_bio.get(), public_key.data(), public_key.size()) != public_key.size())
					throw rsa_exception("failed to load public key: bio_write failed");
				pkey.reset(PEM_read_bio_PUBKEY(pubkey_bio.get(), nullptr, nullptr, (void*)public_key_password.c_str()), EVP_PKEY_free);
				if (!pkey)
					throw rsa_exception("failed to load public key: PEM_read_bio_PUBKEY failed");

				if (!private_key.empty()) {
					std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
					if ((size_t)BIO_write(privkey_bio.get(), private_key.data(), private_key.size()) != private_key.size())
						throw rsa_exception("failed to load private key: bio_write failed");
					RSA* privkey = PEM_read_bio_RSAPrivateKey(privkey_bio.get(), nullptr, nullptr, (void*)private_key_password.c_str());
					if (privkey == nullptr)
						throw rsa_exception("failed to load private key: PEM_read_bio_RSAPrivateKey failed");
					if (EVP_PKEY_assign_RSA(pkey.get(), privkey) == 0) {
						RSA_free(privkey);
						throw rsa_exception("failed to load private key: EVP_PKEY_assign_RSA failed");
					}
				}
			}
			std::string sign(const std::string& data) const {
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
#endif
				if (!ctx)
					throw signature_generation_exception("failed to create signature: could not create context");
				if (!EVP_SignInit(ctx.get(), md()))
					throw signature_generation_exception("failed to create signature: SignInit failed");

				std::string res;
				res.resize(EVP_PKEY_size(pkey.get()));
				unsigned int len = 0;

				if (!EVP_SignUpdate(ctx.get(), data.data(), data.size()))
					throw signature_generation_exception();
				if (!EVP_SignFinal(ctx.get(), (unsigned char*)res.data(), &len, pkey.get()))
					throw signature_generation_exception();

				res.resize(len);
				return res;
			}
			void verify(const std::string& data, const std::string& signature) const {
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
#endif
				if (!ctx)
					throw signature_verification_exception("failed to verify signature: could not create context");
				if (!EVP_VerifyInit(ctx.get(), md()))
					throw signature_verification_exception("failed to verify signature: VerifyInit failed");
				if (!EVP_VerifyUpdate(ctx.get(), data.data(), data.size()))
					throw signature_verification_exception("failed to verify signature: VerifyUpdate failed");
				if (!EVP_VerifyFinal(ctx.get(), (const unsigned char*)signature.data(), signature.size(), pkey.get()))
					throw signature_verification_exception();
			}
			std::string name() const {
				return alg_name;
			}
		private:
			std::shared_ptr<EVP_PKEY> pkey;
			const EVP_MD*(*md)();
			const std::string alg_name;
		};
		struct ecdsa {
			ecdsa(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), const std::string& name)
				: md(md), alg_name(name)
			{
				if (private_key.empty()) {
					std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
					if ((size_t)BIO_write(pubkey_bio.get(), public_key.data(), public_key.size()) != public_key.size())
						throw ecdsa_exception("failed to load public key: bio_write failed");

					pkey.reset(PEM_read_bio_EC_PUBKEY(pubkey_bio.get(), nullptr, nullptr, (void*)public_key_password.c_str()), EC_KEY_free);
					if (!pkey)
						throw ecdsa_exception("failed to load public key: PEM_read_bio_EC_PUBKEY failed");
				} else {
					std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
					if ((size_t)BIO_write(privkey_bio.get(), private_key.data(), private_key.size()) != private_key.size())
						throw ecdsa_exception("failed to load private key: bio_write failed");
					pkey.reset(PEM_read_bio_ECPrivateKey(privkey_bio.get(), nullptr, nullptr, (void*)private_key_password.c_str()), EC_KEY_free);
					if (!pkey)
						throw ecdsa_exception("failed to load private key: PEM_read_bio_RSAPrivateKey failed");
				}

				if(EC_KEY_check_key(pkey.get()) == 0)
					throw ecdsa_exception("failed to load key: key is invalid");
			}
			std::string sign(const std::string& data) const {
				const std::string hash = generate_hash(data);

				std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>
					sig(ECDSA_do_sign((const unsigned char*)hash.data(), hash.size(), pkey.get()), ECDSA_SIG_free);
#ifdef OPENSSL10

				return bn2raw(sig->r) + bn2raw(sig->s);
#else
				const BIGNUM *r;
				const BIGNUM *s;
				ECDSA_SIG_get0(sig.get(), &r, &s);
				return bn2raw(r) + bn2raw(s);
#endif
			}
			void verify(const std::string& data, const std::string& signature) const {
				const std::string hash = generate_hash(data);
				auto r = raw2bn(signature.substr(0, signature.size() / 2));
				auto s = raw2bn(signature.substr(signature.size() / 2));

#ifdef OPENSSL10
				ECDSA_SIG sig;
				sig.r = r.get();
				sig.s = s.get();

				if(ECDSA_do_verify((const unsigned char*)hash.data(), hash.size(), &sig, pkey.get()) != 1)
					throw signature_verification_exception("Invalid signature");
#else
				ECDSA_SIG *sig = ECDSA_SIG_new();

				ECDSA_SIG_set0(sig, r.get(), s.get());

				if(ECDSA_do_verify((const unsigned char*)hash.data(), hash.size(), sig, pkey.get()) != 1)
					throw signature_verification_exception("Invalid signature");
#endif
			}
			std::string name() const {
				return alg_name;
			}
		private:
#ifdef OPENSSL10
			static std::string bn2raw(BIGNUM* bn)
#else
			static std::string bn2raw(const BIGNUM* bn)
#endif
			{
				std::string res;
				res.resize(BN_num_bytes(bn));
				BN_bn2bin(bn, (unsigned char*)res.data());
				if(res.size()%2 == 1 && res[0] == 0x00)
					return res.substr(1);
				return res;
			}
			static std::unique_ptr<BIGNUM, decltype(&BN_free)> raw2bn(const std::string& raw) {
				if(raw[0] >= 0x80) {
					std::string str(1, 0x00);
					str += raw;
					return std::unique_ptr<BIGNUM, decltype(&BN_free)>(BN_bin2bn((const unsigned char*)str.data(), str.size(), nullptr), BN_free);
				}
				return std::unique_ptr<BIGNUM, decltype(&BN_free)>(BN_bin2bn((const unsigned char*)raw.data(), raw.size(), nullptr), BN_free);
			}
			static std::string raw2der(const std::string& raw) {
				std::string res(4, 0x00);
				res[0] = 0x30;
				res[2] = 0x02;
				if (raw[0] & 0x80) {
					res[3] = (char)(raw.size() / 2 + 1);
					res += '\0';
				}
				else {
					res[3] = (char)(raw.size() / 2);
				}
				res += raw.substr(0, raw.size() / 2);
				if (raw[raw.size() / 2] & 0x80) {
					res += 0x02;
					res += (char)(raw.size() / 2 + 1);
					res += '\0';
				}
				else {
					res += (char)(raw.size() / 2);
				}
				res += raw.substr(raw.size() / 2);
				res[1] = (char)(res.size() - 2);
				return res;
			}

			std::string generate_hash(const std::string& data) const {
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
				if(EVP_DigestInit(ctx.get(), md()) == 0)
					throw signature_generation_exception("EVP_DigestInit failed");
				if(EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 0)
					throw signature_generation_exception("EVP_DigestUpdate failed");
				unsigned int len = 0;
				std::string res;
				res.resize(EVP_MD_CTX_block_size(ctx.get()));
				if(EVP_DigestFinal(ctx.get(), (unsigned char*)res.data(), &len) == 0)
					throw signature_generation_exception("EVP_DigestFinal failed");
				res.resize(len);
				return res;
			}

			std::shared_ptr<EC_KEY> pkey;
			const EVP_MD*(*md)();
			const std::string alg_name;
		};

		struct hs256 : public hmacsha {
			hs256(std::string key)
				: hmacsha(std::move(key), EVP_sha256, "HS256")
			{}
		};
		struct hs384 : public hmacsha {
			hs384(std::string key)
				: hmacsha(std::move(key), EVP_sha384, "HS384")
			{}
		};
		struct hs512 : public hmacsha {
			hs512(std::string key)
				: hmacsha(std::move(key), EVP_sha512, "HS512")
			{}
		};
		struct rs256 : public rsa {
			rs256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "RS256")
			{}
		};
		struct rs384 : public rsa {
			rs384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "RS384")
			{}
		};
		struct rs512 : public rsa {
			rs512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "RS512")
			{}
		};
		struct es256 : public ecdsa {
			es256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "ES256")
			{}
		};
		struct es384 : public ecdsa {
			es384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "ES384")
			{}
		};
		struct es512 : public ecdsa {
			es512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "ES512")
			{}
		};
	}

	class claim {
		picojson::value val;
	public:
		enum class type {
			null,
			boolean,
			number,
			string,
			array,
			object,
			int64
		};

		claim()
			: val()
		{}
		claim(std::string s)
			: val(std::move(s))
		{}
		claim(date s)
			: val(int64_t(std::chrono::system_clock::to_time_t(s)))
		{}
		claim(std::set<std::string> s)
			: val(picojson::array(s.cbegin(), s.cend()))
		{}
		claim(const picojson::value& val)
			: val(val)
		{}

		picojson::value to_json() const {
			return val;
		}

		type get_type() const {
			if (val.is<picojson::null>()) return type::null;
			else if (val.is<bool>()) return type::boolean;
			else if (val.is<int64_t>()) return type::int64;
			else if (val.is<double>()) return type::number;
			else if (val.is<std::string>()) return type::string;
			else if (val.is<picojson::array>()) return type::array;
			else if (val.is<picojson::object>()) return type::object;
			else throw std::logic_error("internal error");
		}

		const std::string& as_string() const {
			if (!val.is<std::string>())
				throw std::bad_cast();
			return val.get<std::string>();
		}
		date as_date() const {
			return std::chrono::system_clock::from_time_t(as_int());
		}
		const picojson::array& as_array() const {
			if (!val.is<picojson::array>())
				throw std::bad_cast();
			return val.get<picojson::array>();
		}
		const std::set<std::string> as_set() const {
			std::set<std::string> res;
			for(auto& e : as_array())
				res.insert(e.get<std::string>());
			return res;
		}
		int64_t as_int() const {
			if (!val.is<int64_t>())
				throw std::bad_cast();
			return val.get<int64_t>();
		}
		bool as_bool() const {
			if (!val.is<bool>())
				throw std::bad_cast();
			return val.get<bool>();
		}
	};

	class payload {
	protected:
		std::unordered_map<std::string, claim> payload_claims;
	public:
		bool has_issuer() const noexcept { return has_payload_claim("iss"); }
		bool has_subject() const noexcept { return has_payload_claim("sub"); }
		bool has_audience() const noexcept { return has_payload_claim("aud"); }
		bool has_expires_at() const noexcept { return has_payload_claim("exp"); }
		bool has_not_before() const noexcept { return has_payload_claim("nbf"); }
		bool has_issued_at() const noexcept { return has_payload_claim("iat"); }
		bool has_id() const noexcept { return has_payload_claim("jti"); }
		const std::string& get_issuer() const { return get_payload_claim("iss").as_string(); }
		const std::string& get_subject() const { return get_payload_claim("sub").as_string(); }
		std::set<std::string> get_audience() const { return get_payload_claim("aud").as_set(); }
		const date get_expires_at() const { return get_payload_claim("exp").as_date(); }
		const date get_not_before() const { return get_payload_claim("nbf").as_date(); }
		const date get_issued_at() const { return get_payload_claim("iat").as_date(); }
		const std::string& get_id() const { return get_payload_claim("jti").as_string(); }
		bool has_payload_claim(const std::string& name) const noexcept { return payload_claims.count(name) != 0; }
		const claim& get_payload_claim(const std::string& name) const {
			if (!has_payload_claim(name))
				throw std::runtime_error("claim not found");
			return payload_claims.at(name);
		}
		std::unordered_map<std::string, claim> get_payload_claims() const { return payload_claims; }
	};

	class header {
	protected:
		std::unordered_map<std::string, claim> header_claims;
	public:
		bool has_algorithm() const noexcept { return has_header_claim("alg"); }
		bool has_type() const noexcept { return has_header_claim("typ"); }
		bool has_content_type() const noexcept { return has_header_claim("cty"); }
		bool has_key_id() const noexcept { return has_header_claim("kid"); }
		const std::string& get_algorithm() const { return get_header_claim("alg").as_string(); }
		const std::string& get_type() const { return get_header_claim("typ").as_string(); }
		const std::string& get_content_type() const { return get_header_claim("cty").as_string(); }
		const std::string& get_key_id() const { return get_header_claim("kid").as_string(); }
		bool has_header_claim(const std::string& name) const noexcept { return header_claims.count(name) != 0; }
		const claim& get_header_claim(const std::string& name) const {
			if (!has_header_claim(name))
				throw std::runtime_error("claim not found");
			return header_claims.at(name);
		}
		std::unordered_map<std::string, claim> get_header_claims() const { return header_claims; }
	};

	class decoded_jwt : public header, public payload {
	protected:
		std::string token;
		std::string header;
		std::string header_base64;
		std::string payload;
		std::string payload_base64;
		std::string signature;
		std::string signature_base64;
	public:
		decoded_jwt(const std::string& token)
			: token(token)
		{
			auto hdr_end = token.find('.');
			if (hdr_end == std::string::npos)
				throw std::invalid_argument("invalid token supplied");
			auto payload_end = token.find('.', hdr_end + 1);
			if (hdr_end == std::string::npos)
				throw std::invalid_argument("invalid token supplied");
			header = header_base64 = token.substr(0, hdr_end);
			payload = payload_base64 = token.substr(hdr_end + 1, payload_end - hdr_end - 1);
			signature = signature_base64 = token.substr(payload_end + 1);

			// Fix padding: JWT requires padding to get removed
			auto fix_padding = [](std::string& str) {
				switch (str.size() % 4) {
				case 1:
					str += alphabet::base64url::fill();
				case 2:
					str += alphabet::base64url::fill();
				case 3:
					str += alphabet::base64url::fill();
				default:
					break;
				}
			};
			fix_padding(header);
			fix_padding(payload);
			fix_padding(signature);

			header = base::decode<alphabet::base64url>(header);
			payload = base::decode<alphabet::base64url>(payload);
			signature = base::decode<alphabet::base64url>(signature);

			auto parse_claims = [](const std::string& str) {
				std::unordered_map<std::string, claim> res;
				picojson::value val;
				if (!picojson::parse(val, str).empty())
					throw std::runtime_error("Invalid json");

				for (auto& e : val.get<picojson::object>()) { res.insert({ e.first, e.second }); }

				return res;
			};

			header_claims = parse_claims(header);
			payload_claims = parse_claims(payload);
		}

		const std::string& get_token() const { return token; }
		const std::string& get_header() const { return header; }
		const std::string& get_payload() const { return payload; }
		const std::string& get_signature() const { return signature; }
		const std::string& get_header_base64() const { return header_base64; }
		const std::string& get_payload_base64() const { return payload_base64; }
		const std::string& get_signature_base64() const { return signature_base64; }

	};

	class builder {
		std::unordered_map<std::string, claim> header_claims;
		std::unordered_map<std::string, claim> payload_claims;

		builder() {}
		friend builder create();
	public:
		builder& set_header_claim(const std::string& id, claim c) { header_claims[id] = c; return *this; }
		builder& set_payload_claim(const std::string& id, claim c) { payload_claims[id] = c; return *this; }
		builder& set_algorithm(const std::string& str) { return set_header_claim("alg", str); }
		builder& set_type(const std::string& str) { return set_header_claim("typ", str); }
		builder& set_content_type(const std::string& str) { return set_header_claim("cty", str); }
		builder& set_key_id(const std::string& str) { return set_header_claim("kid", str); }
		builder& set_issuer(const std::string& str) { return set_payload_claim("iss", str); }
		builder& set_subject(const std::string& str) { return set_payload_claim("sub", str); }
		builder& set_audience(const std::set<std::string>& l) { return set_payload_claim("aud", l); }
		builder& set_expires_at(date d) { return set_payload_claim("exp", d); }
		builder& set_not_before(date d) { return set_payload_claim("nbf", d); }
		builder& set_issued_at(date d) { return set_payload_claim("iat", d); }
		builder& set_id(const std::string& str) { return set_payload_claim("jti", str); }

		template<typename T>
		std::string sign(const T& algo) {
			this->set_algorithm(algo.name());

			picojson::object obj_header;
			for (auto& e : header_claims) {
				obj_header.insert({ e.first, e.second.to_json() });
			}
			picojson::object obj_payload;
			for (auto& e : payload_claims) {
				obj_payload.insert({ e.first, e.second.to_json() });
			}

			auto encode = [](const std::string& data) {
				auto base = base::encode<alphabet::base64url>(data);
				auto pos = base.find(alphabet::base64url::fill());
				base = base.substr(0, pos);
				return base;
			};

			std::string header = encode(picojson::value(obj_header).serialize());
			std::string payload = encode(picojson::value(obj_payload).serialize());

			std::string token = header + "." + payload;

			return token + "." + encode(algo.sign(token));
		}
	};

	template<typename Clock>
	class verifier {
		struct algo_base {
			virtual void verify(const std::string& data, const std::string& sig) = 0;
		};
		template<typename T>
		struct algo : public algo_base {
			T alg;
			algo(T a) : alg(a) {}
			virtual void verify(const std::string& data, const std::string& sig) {
				alg.verify(data, sig);
			}
		};

		std::unordered_map<std::string, claim> claims;
		size_t default_leeway = 0;
		Clock clock;
		std::unordered_map<std::string, std::shared_ptr<algo_base>> algs;
	public:
		verifier(Clock c) : clock(c) {}

		verifier& leeway(size_t leeway) { default_leeway = leeway; return *this; }
		verifier& expires_at_leeway(size_t leeway) { return with_claim("exp", std::chrono::system_clock::from_time_t(leeway)); }
		verifier& not_before_leeway(size_t leeway) { return with_claim("nbf", std::chrono::system_clock::from_time_t(leeway)); }
		verifier& issued_at_leeway(size_t leeway) { return with_claim("iat", std::chrono::system_clock::from_time_t(leeway)); }
		verifier& with_issuer(const std::string& iss) { return with_claim("iss", iss); }
		verifier& with_subject(const std::string& sub) { return with_claim("sub", sub); }
		verifier& with_audience(const std::set<std::string>& aud) { return with_claim("aud", aud); }
		verifier& with_id(const std::string& id) { return with_claim("jti", id); }
		verifier& with_claim(const std::string& name, claim c) { claims[name] = c; return *this; }

		template<typename Algorithm>
		verifier& allow_algorithm(Algorithm alg) {
			algs[alg.name()] = std::make_shared<algo<Algorithm>>(alg);
			return *this;
		}

		void verify(const decoded_jwt& jwt) const {
			const std::string data = jwt.get_header_base64() + "." + jwt.get_payload_base64();
			const std::string sig = jwt.get_signature();
			const std::string& algo = jwt.get_algorithm();
			if (algs.count(algo) == 0)
				throw token_verification_exception("wrong algorithm");
			algs.at(algo)->verify(data, sig);

			auto assert_claim_eq = [](const decoded_jwt& jwt, const std::string& key, const claim& c) {
				if (!jwt.has_payload_claim(key))
					throw token_verification_exception("decoded_jwt is missing " + key + " claim");
				auto& jc = jwt.get_payload_claim(key);
				if (jc.get_type() != c.get_type())
					throw token_verification_exception("claim " + key + " type mismatch");
				if (c.get_type() == claim::type::int64) {
					if (c.as_date() != jc.as_date())
						throw token_verification_exception("claim " + key + " does not match expected");
				}
				else if (c.get_type() == claim::type::array) {
					auto s1 = c.as_set();
					auto s2 = jc.as_set();
					if (s1.size() != s2.size())
						throw token_verification_exception("claim " + key + " does not match expected");
					auto it1 = s1.cbegin();
					auto it2 = s2.cbegin();
					while (it1 != s1.cend() && it2 != s2.cend()) {
						if (*it1++ != *it2++)
							throw token_verification_exception("claim " + key + " does not match expected");
					}
				}
				else if (c.get_type() == claim::type::string) {
					if (c.as_string() != jc.as_string())
						throw token_verification_exception("claim " + key + " does not match expected");
				}
				else throw token_verification_exception("internal error");
			};

			auto time = clock.now();

			if (jwt.has_expires_at()) {
				auto leeway = claims.count("exp") == 1 ? std::chrono::system_clock::to_time_t(claims.at("exp").as_date()) : default_leeway;
				auto exp = jwt.get_expires_at();
				if (time > exp + std::chrono::seconds(leeway))
					throw token_verification_exception("token expired");
			}
			if (jwt.has_issued_at()) {
				auto leeway = claims.count("iat") == 1 ? std::chrono::system_clock::to_time_t(claims.at("iat").as_date()) : default_leeway;
				auto iat = jwt.get_issued_at();
				if (time < iat - std::chrono::seconds(leeway))
					throw token_verification_exception("token expired");
			}
			if (jwt.has_not_before()) {
				auto leeway = claims.count("nbf") == 1 ? std::chrono::system_clock::to_time_t(claims.at("nbf").as_date()) : default_leeway;
				auto nbf = jwt.get_not_before();
				if (time < nbf - std::chrono::seconds(leeway))
					throw token_verification_exception("token expired");
			}
			for (auto& c : claims)
			{
				if (c.first == "exp" || c.first == "iat" || c.first == "nbf") {
					// Nothing to do here, already checked
				}
				else if (c.first == "aud") {
					if (!jwt.has_audience())
						throw token_verification_exception("token doesn't contain the required audience");
					auto aud = jwt.get_audience();
					auto expected = c.second.as_set();
					for (auto& e : expected)
						if (aud.count(e) == 0)
							throw token_verification_exception("token doesn't contain the required audience");
				}
				else {
					assert_claim_eq(jwt, c.first, c.second);
				}
			}
		}
	};

	template<typename Clock>
	verifier<Clock> verify(Clock c) {
		return verifier<Clock>(c);
	}

	struct default_clock {
		std::chrono::system_clock::time_point now() const {
			return std::chrono::system_clock::now();
		}
	};

    inline
	verifier<default_clock> verify() {
		return verify<default_clock>({});
	}

    inline
	builder create() {
		return builder();
	}

    inline
	decoded_jwt decode(const std::string& token) {
		return decoded_jwt(token);
	}
}
