#ifndef JWT_CPP_JWT_H
#define JWT_CPP_JWT_H

#ifndef DISABLE_PICOJSON
#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include "picojson/picojson.h"
#endif

#ifndef DISABLE_BASE64
#include "base.h"
#endif

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>

#include <chrono>
#include <memory>
#include <set>
#include <unordered_map>
#include <utility>
#include <type_traits>

#if __cplusplus >= 201402L
#ifdef __has_include
#if __has_include(<experimental/type_traits>)
#include <experimental/type_traits>
#endif
#endif
#endif

//If openssl version less than 1.1
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OPENSSL10
#endif

#ifndef JWT_CLAIM_EXPLICIT
#define JWT_CLAIM_EXPLICIT explicit
#endif

/**
 * \brief JSON Web Token
 * 
 * A namespace to contain everything related to handling JSON Web Tokens, JWT for short,
 * as a part of [RFC7519](https://tools.ietf.org/html/rfc7519), or alternatively for
 * JWS (JSON Web Signature)from [RFC7515](https://tools.ietf.org/html/rfc7515)
 */ 
namespace jwt {
	using date = std::chrono::system_clock::time_point;

	struct signature_verification_exception : public std::runtime_error {
		signature_verification_exception()
			: std::runtime_error("signature verification failed")
		{}
		explicit signature_verification_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		explicit signature_verification_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct signature_generation_exception : public std::runtime_error {
		signature_generation_exception()
			: std::runtime_error("signature generation failed")
		{}
		explicit signature_generation_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		explicit signature_generation_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct rsa_exception : public std::runtime_error {
		explicit rsa_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		explicit rsa_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct ecdsa_exception : public std::runtime_error {
		explicit ecdsa_exception(const std::string& msg)
			: std::runtime_error(msg)
		{}
		explicit ecdsa_exception(const char* msg)
			: std::runtime_error(msg)
		{}
	};
	struct token_verification_exception : public std::runtime_error {
		token_verification_exception()
			: std::runtime_error("token verification failed")
		{}
		explicit token_verification_exception(const std::string& msg)
			: std::runtime_error("token verification failed: " + msg)
		{}
	};

	/**
	 * \brief Everything related to error codes issued by the library
	 */
	namespace error {
		/**
		 * \brief Error related to processing of RSA signatures
		 */
		enum class rsa_error {
			ok = 0,
			cert_load_failed = 10,
			get_key_failed,
			write_key_failed,
			convert_to_pem_failed,
			load_key_bio_write,
			load_key_bio_read,
			create_mem_bio_failed,
		};
		/**
		 * \brief Errorcategory for RSA errors
		 */
		inline std::error_category& rsa_error_category() {
			class rsa_error_cat : public std::error_category
			{
			public:
				const char* name() const noexcept override { return "rsa_error"; };
				std::string message(int ev) const override {
					switch(static_cast<rsa_error>(ev)) {
					case rsa_error::ok: return "no error";
					case rsa_error::cert_load_failed: return "error loading cert into memory";
					case rsa_error::get_key_failed: return "error getting key from certificate";
					case rsa_error::write_key_failed: return "error writing key data in PEM format";
					case rsa_error::convert_to_pem_failed: return "failed to convert key to pem";
					case rsa_error::load_key_bio_write: return "failed to load key: bio write failed";
					case rsa_error::load_key_bio_read: return "failed to load key: bio read failed";
					case rsa_error::create_mem_bio_failed: return "failed to create memory bio";
					default: return "unknown error code";
					}
				}
			};
			static rsa_error_cat cat = {};
			return cat;
		}
		
		inline std::error_code make_error_code(rsa_error e) {
			return {static_cast<int>(e), rsa_error_category()};
		}

		/**
		 * \brief Errors related to verification of signatures
		 */
		enum class signature_verification_error {
			ok = 0,
			invalid_signature = 10,
			create_context_failed,
			verifyinit_failed,
			verifyupdate_failed,
			verifyfinal_failed,
			get_key_failed
		};
		/**
		 * \brief Errorcategory for verification errors
		 */
		inline std::error_category& signature_verification_error_category() {
			class verification_error_cat : public std::error_category
			{
			public:
				const char* name() const noexcept override { return "verification_error"; };
				std::string message(int ev) const override {
					switch(static_cast<signature_verification_error>(ev)) {
					case signature_verification_error::ok: return "no error";
					case signature_verification_error::invalid_signature: return "invalid signature";
					case signature_verification_error::create_context_failed: return "failed to verify signature: could not create context";
					case signature_verification_error::verifyinit_failed: return "failed to verify signature: VerifyInit failed";
					case signature_verification_error::verifyupdate_failed: return "failed to verify signature: VerifyUpdate failed";
					case signature_verification_error::verifyfinal_failed: return "failed to verify signature: VerifyFinal failed";
					case signature_verification_error::get_key_failed: return "failed to verify signature: Could not get key";
					default: return "unknown error code";
					}
				}
			};
			static verification_error_cat cat = {};
			return cat;
		}

		inline std::error_code make_error_code(signature_verification_error e) {
			return {static_cast<int>(e), signature_verification_error_category()};
		}

		inline void throw_if_error(std::error_code ec) {
			if(ec) {
				if(ec.category() == rsa_error_category())
					throw rsa_exception(ec.message());
				if(ec.category() == signature_verification_error_category())
					throw signature_verification_exception(ec.message());
			}
		}
	}
}
namespace std
{
	template <>
	struct is_error_code_enum<jwt::error::rsa_error> : true_type {};
	template <>
	struct is_error_code_enum<jwt::error::signature_verification_error> : true_type {};
}
namespace jwt {
	/**
	 * \brief A collection for working with certificates
	 * 
	 * These _helpers_ are usefully when working with certificates OpenSSL APIs.
	 * For example, when dealing with JWKS (JSON Web Key Set)[https://tools.ietf.org/html/rfc7517]
	 * you maybe need to extract the modulus and exponent of an RSA Public Key.
	 */ 
	namespace helper {
		/**
		 * \brief Extract the public key of a pem certificate
		 * 
		 * \param certstr	String containing the certificate encoded as pem
		 * \param pw		Password used to decrypt certificate (leave empty if not encrypted)
		 * \param ec		error_code for error_detection (gets cleared if no error occures)
		 */
		inline
		std::string extract_pubkey_from_cert(const std::string& certstr, const std::string& pw, std::error_code& ec) {
			ec.clear();
#if OPENSSL_VERSION_NUMBER <= 0x10100003L
			std::unique_ptr<BIO, decltype(&BIO_free_all)> certbio(BIO_new_mem_buf(const_cast<char*>(certstr.data()), certstr.size()), BIO_free_all);
#else
			std::unique_ptr<BIO, decltype(&BIO_free_all)> certbio(BIO_new_mem_buf(certstr.data(), static_cast<int>(certstr.size())), BIO_free_all);
#endif
			std::unique_ptr<BIO, decltype(&BIO_free_all)> keybio(BIO_new(BIO_s_mem()), BIO_free_all);
			if(!certbio || !keybio) {
				ec = error::rsa_error::create_mem_bio_failed;
				return "";
			}

			std::unique_ptr<X509, decltype(&X509_free)> cert(PEM_read_bio_X509(certbio.get(), nullptr, nullptr, const_cast<char*>(pw.c_str())), X509_free);
			if (!cert) {
				ec = error::rsa_error::cert_load_failed;
				return "";
			}
			std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(X509_get_pubkey(cert.get()), EVP_PKEY_free);
			if(!key) {
				ec = error::rsa_error::get_key_failed;
				return "";
			}
			if(PEM_write_bio_PUBKEY(keybio.get(), key.get()) == 0) {
				ec = error::rsa_error::write_key_failed;
				return "";
			}
			char* ptr = nullptr;
			auto len = BIO_get_mem_data(keybio.get(), &ptr);
			if(len <= 0 || ptr == nullptr) {
				ec = error::rsa_error::convert_to_pem_failed;
				return "";
			}
			std::string res(ptr, len);
			return res;
		}

		/**
		 * \brief Extract the public key of a pem certificate
		 * 
		 * \param certstr	String containing the certificate encoded as pem
		 * \param pw		Password used to decrypt certificate (leave empty if not encrypted)
		 * \throws	rsa_exception if an error occurred
		 */
		inline
		std::string extract_pubkey_from_cert(const std::string& certstr, const std::string& pw = "") {
			std::error_code ec;
			auto res = extract_pubkey_from_cert(certstr, pw, ec);
			error::throw_if_error(ec);
			return res;
		}

		/**
		 * \brief Load a public key from a string.
		 * 
		 * The string should contain a pem encoded certificate or public key
		 * 
		 * \param certstr	String containing the certificate encoded as pem
		 * \param pw		Password used to decrypt certificate (leave empty if not encrypted)
		 * \param ec		error_code for error_detection (gets cleared if no error occures)
		 */
		inline
		std::shared_ptr<EVP_PKEY> load_public_key_from_string(const std::string& key, const std::string& password, std::error_code& ec) {
			ec.clear();
			std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
			if(!pubkey_bio) {
				ec = error::rsa_error::create_mem_bio_failed;
				return nullptr;
			}
			if(key.substr(0, 27) == "-----BEGIN CERTIFICATE-----") {
				auto epkey = helper::extract_pubkey_from_cert(key, password, ec);
				if(ec) return nullptr;
				const int len = static_cast<int>(epkey.size());
				if (BIO_write(pubkey_bio.get(), epkey.data(), len) != len) {
					ec = error::rsa_error::load_key_bio_write;
					return nullptr;
				}
			} else {
				const int len = static_cast<int>(key.size());
				if (BIO_write(pubkey_bio.get(), key.data(), len) != len) {
					ec = error::rsa_error::load_key_bio_write;
					return nullptr;
				}
			}
			
			std::shared_ptr<EVP_PKEY> pkey(PEM_read_bio_PUBKEY(pubkey_bio.get(), nullptr, nullptr, (void*)password.data()), EVP_PKEY_free);  // NOLINT(google-readability-casting) requires `const_cast`
			if (!pkey) {
				ec = error::rsa_error::load_key_bio_read;
				return nullptr;
			}
			return pkey;
		}

		/**
		 * \brief Load a public key from a string.
		 * 
		 * The string should contain a pem encoded certificate or public key
		 * 
		 * \param certstr	String containing the certificate or key encoded as pem
		 * \param pw		Password used to decrypt certificate or key (leave empty if not encrypted)
		 * \throws	rsa_exception if an error occurred
		 */
		inline
		std::shared_ptr<EVP_PKEY> load_public_key_from_string(const std::string& key, const std::string& password = "") {
			std::error_code ec;
			auto res = load_public_key_from_string(key, password, ec);
			error::throw_if_error(ec);
			return res;
		}

		/**
		 * \brief Load a private key from a string.
		 * 
		 * \param key		String containing a private key as pem
		 * \param pw		Password used to decrypt key (leave empty if not encrypted)
		 * \param ec		error_code for error_detection (gets cleared if no error occures)
		 */
		inline
		std::shared_ptr<EVP_PKEY> load_private_key_from_string(const std::string& key, const std::string& password, std::error_code& ec) {
			std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
			if(!privkey_bio) {
				ec = error::rsa_error::create_mem_bio_failed;
				return nullptr;
			}
			const int len = static_cast<int>(key.size());
			if (BIO_write(privkey_bio.get(), key.data(), len) != len) {
				ec = error::rsa_error::load_key_bio_write;
				return nullptr;
			}
			std::shared_ptr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(privkey_bio.get(), nullptr, nullptr, const_cast<char*>(password.c_str())), EVP_PKEY_free);
			if (!pkey) {
				ec = error::rsa_error::load_key_bio_read;
				return nullptr;
			}
			return pkey;
		}

		/**
		 * \brief Load a private key from a string.
		 * 
		 * \param key		String containing a private key as pem
		 * \param pw		Password used to decrypt key (leave empty if not encrypted)
		 * \throws	rsa_exception if an error occurred
		 */
		inline
		std::shared_ptr<EVP_PKEY> load_private_key_from_string(const std::string& key, const std::string& password = "") {
			std::error_code ec;
			auto res = load_private_key_from_string(key, password, ec);
			error::throw_if_error(ec);
			return res;
		}
		
		/**
		 * Convert a OpenSSL BIGNUM to a std::string
		 * \param bn BIGNUM to convert
		 * \return bignum as string
		 */
		inline
#ifdef OPENSSL10
		static std::string bn2raw(BIGNUM* bn)
#else
		static std::string bn2raw(const BIGNUM* bn)
#endif
		{
			std::string res;
			res.resize(BN_num_bytes(bn));
			BN_bn2bin(bn, (unsigned char*)res.data());  // NOLINT(google-readability-casting) requires `const_cast`
			return res;
		}
		/**
		 * Convert an std::string to a OpenSSL BIGNUM
		 * \param raw String to convert
		 * \return BIGNUM representation
		 */
		inline
		static std::unique_ptr<BIGNUM, decltype(&BN_free)> raw2bn(const std::string& raw) {
			return std::unique_ptr<BIGNUM, decltype(&BN_free)>(BN_bin2bn(reinterpret_cast<const unsigned char*>(raw.data()), static_cast<int>(raw.size()), nullptr), BN_free);
		}
	}  // namespace helper

	/**
	 * \brief Various cryptographic algorithms when working with JWT
	 * 
	 * JWT (JSON Web Tokens) signatures are typically used as the payload for a JWS (JSON Web Signature) or
	 * JWE (JSON Web Encryption). Both of these use various cryptographic as specified by [RFC7518](https://tools.ietf.org/html/rfc7518)
	 * and are exposed through the a [JOSE Header](https://tools.ietf.org/html/rfc7515#section-4) which 
	 * points to one of the JWA (JSON Web Algorithms)(https://tools.ietf.org/html/rfc7518#section-3.1)
	 */
	namespace algorithm {
		/**
		 * \brief "none" algorithm.
		 * 
		 * Returns and empty signature and checks if the given signature is empty.
		 */
		struct none {
			/**
			 * \brief Return an empty string
			 */ 
			std::string sign(const std::string& /*unused*/) const {
				return "";
			}
			/**
			 * \brief Check if the given signature is empty.
			 * 
			 * JWT's with "none" algorithm should not contain a signature.
			 * \throw signature_verification_exception
			 */ 
			void verify(const std::string& /*unused*/, const std::string& signature) const {
				if (!signature.empty())
					throw signature_verification_exception();
			}
			/**
			 * \brief Check if the given signature is empty.
			 * 
			 * JWT's with "none" algorithm should not contain a signature.
			 * \param signature Signature data to verify
			 * \param ec		error_code filled with details about the error
			 */
			void verify(const std::string& /*unused*/, const std::string& signature, std::error_code& ec) const {
				ec.clear();
				if (!signature.empty()) {
					ec = error::signature_verification_error::invalid_signature;
				}
			}
			/// Get algorithm name
			std::string name() const {
				return "none";
			}
		};
		/**
		 * \brief Base class for HMAC family of algorithms
		 */
		struct hmacsha {
			/**
			 * Construct new hmac algorithm
			 * \param key Key to use for HMAC
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			hmacsha(std::string key, const EVP_MD*(*md)(), std::string  name)
				: secret(std::move(key)), md(md), alg_name(std::move(name))
			{}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return HMAC signature for the given data
			 * \throw signature_generation_exception
			 */
			std::string sign(const std::string& data) const {
				std::string res;
				res.resize(static_cast<size_t>(EVP_MAX_MD_SIZE));
				auto len = static_cast<unsigned int>(res.size());
				if (HMAC(md(), secret.data(), static_cast<int>(secret.size()), reinterpret_cast<const unsigned char*>(data.data()), static_cast<int>(data.size()), (unsigned char*)res.data(), &len) == nullptr)  // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_generation_exception();
				res.resize(len);
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \throw signature_verification_exception If the provided signature does not match
			 */
			void verify(const std::string& data, const std::string& signature) const {
				std::error_code ec;
				verify(data, signature, ec);
				error::throw_if_error(ec);
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec Filled with details about failure.
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
				ec.clear();
				try {
					auto res = sign(data);
					bool matched = true;
					for (size_t i = 0; i < std::min<size_t>(res.size(), signature.size()); i++)
						if (res[i] != signature[i])
							matched = false;
					if (res.size() != signature.size())
						matched = false;
					if (!matched) {
						ec = error::signature_verification_error::invalid_signature;
						return;
					}
				}
				catch (const signature_generation_exception&) {
					ec = error::signature_verification_error::invalid_signature;
				}
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return algorithm's name
			 */
			std::string name() const {
				return alg_name;
			}
		private:
			/// HMAC secrect
			const std::string secret;
			/// HMAC hash generator
			const EVP_MD*(*md)();
			/// algorithm's name
			const std::string alg_name;
		};
		/**
		 * \brief Base class for RSA family of algorithms
		 */
		struct rsa {
			/**
			 * Construct new rsa algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			rsa(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), std::string  name)
				: md(md), alg_name(std::move(name))
			{
				if (!private_key.empty()) {
					pkey = helper::load_private_key_from_string(private_key, private_key_password);
				} else if(!public_key.empty()) {
					pkey = helper::load_public_key_from_string(public_key, public_key_password);
				} else
					throw rsa_exception("at least one of public or private key need to be present");
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return RSA signature for the given data
			 * \throw signature_generation_exception
			 */
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
				if (EVP_SignFinal(ctx.get(), (unsigned char*)res.data(), &len, pkey.get()) == 0)   // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_generation_exception();

				res.resize(len);
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \throw signature_verification_exception If the provided signature does not match
			 */
			void verify(const std::string& data, const std::string& signature) const {
				std::error_code ec;
				verify(data, signature, ec);
				error::throw_if_error(ec);
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec Filled with details on failure
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
				ec.clear();
#ifdef OPENSSL10
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
#endif
				if (!ctx) {
					ec = error::signature_verification_error::create_context_failed;
					return;
				}
				if (!EVP_VerifyInit(ctx.get(), md())) {
					ec = error::signature_verification_error::verifyinit_failed;
					return;
				}
				if (!EVP_VerifyUpdate(ctx.get(), data.data(), data.size())) {
					ec = error::signature_verification_error::verifyupdate_failed;
					return;
				}
				auto res = EVP_VerifyFinal(ctx.get(), reinterpret_cast<const unsigned char*>(signature.data()), static_cast<unsigned int>(signature.size()), pkey.get());
				if (res != 1) {
					ec = error::signature_verification_error::verifyfinal_failed;
					return;
				}
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return algorithm's name
			 */
			std::string name() const {
				return alg_name;
			}
		private:
			/// OpenSSL structure containing converted keys
			std::shared_ptr<EVP_PKEY> pkey;
			/// Hash generator
			const EVP_MD*(*md)();
			/// algorithm's name
			const std::string alg_name;
		};
		/**
		 * \brief Base class for ECDSA family of algorithms
		 */
		struct ecdsa {
			/**
			 * Construct new ecdsa algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			ecdsa(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), std::string  name, size_t siglen)
				: md(md), alg_name(std::move(name)), signature_length(siglen)
			{
				if (!public_key.empty()) {
					std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
					if(public_key.substr(0, 27) == "-----BEGIN CERTIFICATE-----") {
						auto epkey = helper::extract_pubkey_from_cert(public_key, public_key_password);
						const int len = static_cast<int>(epkey.size());
						if (BIO_write(pubkey_bio.get(), epkey.data(), len) != len)
							throw ecdsa_exception("failed to load public key: bio_write failed");
					} else  {
						const int len = static_cast<int>(public_key.size());
						if (BIO_write(pubkey_bio.get(), public_key.data(), len) != len)
							throw ecdsa_exception("failed to load public key: bio_write failed");
					}

					pkey.reset(PEM_read_bio_EC_PUBKEY(pubkey_bio.get(), nullptr, nullptr, (void*)public_key_password.c_str()), EC_KEY_free);  // NOLINT(google-readability-casting) requires `const_cast`
					if (!pkey)
						throw ecdsa_exception("failed to load public key: PEM_read_bio_EC_PUBKEY failed:" + std::string(ERR_error_string(ERR_get_error(), nullptr)));
					size_t keysize = EC_GROUP_get_degree(EC_KEY_get0_group(pkey.get()));
					if(keysize != signature_length*4 && (signature_length != 132 || keysize != 521))
						throw ecdsa_exception("invalid key size");
				}

				if (!private_key.empty()) {
					std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
						const int len = static_cast<int>(private_key.size());
					if (BIO_write(privkey_bio.get(), private_key.data(), len) != len)
						throw ecdsa_exception("failed to load private key: bio_write failed");
					pkey.reset(PEM_read_bio_ECPrivateKey(privkey_bio.get(), nullptr, nullptr, const_cast<char*>(private_key_password.c_str())), EC_KEY_free);
					if (!pkey)
						throw ecdsa_exception("failed to load private key: PEM_read_bio_ECPrivateKey failed");
					size_t keysize = EC_GROUP_get_degree(EC_KEY_get0_group(pkey.get()));
					if(keysize != signature_length*4 && (signature_length != 132 || keysize != 521))
						throw ecdsa_exception("invalid key size");
				}
				if(!pkey)
					throw ecdsa_exception("at least one of public or private key need to be present");

				if(EC_KEY_check_key(pkey.get()) == 0)
					throw ecdsa_exception("failed to load key: key is invalid");
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return ECDSA signature for the given data
			 * \throw signature_generation_exception
			 */
			std::string sign(const std::string& data) const {
				const std::string hash = generate_hash(data);

				std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>
					sig(ECDSA_do_sign(reinterpret_cast<const unsigned char*>(hash.data()), static_cast<int>(hash.size()), pkey.get()), ECDSA_SIG_free);
				if(!sig)
					throw signature_generation_exception();
#ifdef OPENSSL10

				auto rr = helper::bn2raw(sig->r);
				auto rs = helper::bn2raw(sig->s);
#else
				const BIGNUM *r;
				const BIGNUM *s;
				ECDSA_SIG_get0(sig.get(), &r, &s);
				auto rr = helper::bn2raw(r);
				auto rs = helper::bn2raw(s);
#endif
				if(rr.size() > signature_length/2 || rs.size() > signature_length/2)
					throw std::logic_error("bignum size exceeded expected length");
				rr.insert(0, signature_length/2 - rr.size(), '\0');
				rs.insert(0, signature_length/2 - rs.size(), '\0');
				return rr + rs;
			}

			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \throw signature_verification_exception If the provided signature does not match
			 */
			void verify(const std::string& data, const std::string& signature) const {
				std::error_code ec;
				verify(data, signature, ec);
				error::throw_if_error(ec);
			}

			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec Filled with details on error
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
				const std::string hash = generate_hash(data);
				auto r = helper::raw2bn(signature.substr(0, signature.size() / 2));
				auto s = helper::raw2bn(signature.substr(signature.size() / 2));

#ifdef OPENSSL10
				ECDSA_SIG sig;
				sig.r = r.get();
				sig.s = s.get();

				if(ECDSA_do_verify((const unsigned char*)hash.data(), hash.size(), &sig, pkey.get()) != 1) {
					ec = error::signature_verification_error::invalid_signature;
					return;
				}
#else
				std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(ECDSA_SIG_new(), ECDSA_SIG_free);
				if(!sig) {
					ec = error::signature_verification_error::create_context_failed;
					return;
				}

				ECDSA_SIG_set0(sig.get(), r.release(), s.release());

				if(ECDSA_do_verify(reinterpret_cast<const unsigned char*>(hash.data()), static_cast<int>(hash.size()), sig.get(), pkey.get()) != 1) {
					ec = error::signature_verification_error::invalid_signature;
					return;
				}
#endif
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return algorithm's name
			 */
			std::string name() const {
				return alg_name;
			}
		private:
			/**
			 * Hash the provided data using the hash function specified in constructor
			 * \param data Data to hash
			 * \return Hash of data
			 */
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
				res.resize(EVP_MD_CTX_size(ctx.get()));
				if(EVP_DigestFinal(ctx.get(), (unsigned char*)res.data(), &len) == 0) // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_generation_exception("EVP_DigestFinal failed");
				res.resize(len);
				return res;
			}

			/// OpenSSL struct containing keys
			std::shared_ptr<EC_KEY> pkey;
			/// Hash generator function
			const EVP_MD*(*md)();
			/// algorithm's name
			const std::string alg_name;
			/// Length of the resulting signature
			const size_t signature_length;
		};

		/**
		 * \brief Base class for PSS-RSA family of algorithms
		 */
		struct pss {
			/**
			 * Construct new pss algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			pss(const std::string& public_key, const std::string& private_key, const std::string& public_key_password, const std::string& private_key_password, const EVP_MD*(*md)(), std::string  name)
				: md(md), alg_name(std::move(name))
			{
				if (!private_key.empty()) {
					pkey = helper::load_private_key_from_string(private_key, private_key_password);
				} else if(!public_key.empty()) {
					pkey = helper::load_public_key_from_string(public_key, public_key_password);
				} else
					throw rsa_exception("at least one of public or private key need to be present");
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \return ECDSA signature for the given data
			 * \throw signature_generation_exception
			 */
			std::string sign(const std::string& data) const {
				auto hash = this->generate_hash(data);

				std::unique_ptr<RSA, decltype(&RSA_free)> key(EVP_PKEY_get1_RSA(pkey.get()), RSA_free);
				const int size = RSA_size(key.get());

				std::string padded(size, 0x00);
				if (RSA_padding_add_PKCS1_PSS_mgf1(key.get(), (unsigned char*)padded.data(), reinterpret_cast<const unsigned char*>(hash.data()), md(), md(), -1) == 0) // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_generation_exception("failed to create signature: RSA_padding_add_PKCS1_PSS_mgf1 failed");

				std::string res(size, 0x00);
				if (RSA_private_encrypt(size, reinterpret_cast<const unsigned char*>(padded.data()), (unsigned char*)res.data(), key.get(), RSA_NO_PADDING) < 0) // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_generation_exception("failed to create signature: RSA_private_encrypt failed");
				return res;
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \throw signature_verification_exception If the provided signature does not match
			 */
			void verify(const std::string& data, const std::string& signature) const {
				std::error_code ec;
				verify(data, signature, ec);
				error::throw_if_error(ec);
			}
			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec Filled with error details
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
				ec.clear();
				auto hash = this->generate_hash(data);

				std::unique_ptr<RSA, decltype(&RSA_free)> key(EVP_PKEY_get1_RSA(pkey.get()), RSA_free);
				if(!key) {
					ec = error::signature_verification_error::get_key_failed;
					return;
				}
				const int size = RSA_size(key.get());
				
				std::string sig(size, 0x00);
				if(RSA_public_decrypt(static_cast<int>(signature.size()), reinterpret_cast<const unsigned char*>(signature.data()), (unsigned char*)sig.data(), key.get(), RSA_NO_PADDING) == 0) {// NOLINT(google-readability-casting) requires `const_cast`
					ec = error::signature_verification_error::invalid_signature;
					return;
				}
				
				if(RSA_verify_PKCS1_PSS_mgf1(key.get(), reinterpret_cast<const unsigned char*>(hash.data()), md(), md(), reinterpret_cast<const unsigned char*>(sig.data()), -1) == 0) {
					ec = error::signature_verification_error::invalid_signature;
					return;
				}
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return algorithm's name
			 */
			std::string name() const {
				return alg_name;
			}
		private:
			/**
			 * Hash the provided data using the hash function specified in constructor
			 * \param data Data to hash
			 * \return Hash of data
			 */
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
				res.resize(EVP_MD_CTX_size(ctx.get()));
				if(EVP_DigestFinal(ctx.get(), (unsigned char*)res.data(), &len) == 0) // NOLINT(google-readability-casting) requires `const_cast`
					throw signature_generation_exception("EVP_DigestFinal failed");
				res.resize(len);
				return res;
			}
			
			/// OpenSSL structure containing keys
			std::shared_ptr<EVP_PKEY> pkey;
			/// Hash generator function
			const EVP_MD*(*md)();
			/// algorithm's name
			const std::string alg_name;
		};

		/**
		 * HS256 algorithm
		 */
		struct hs256 : public hmacsha {
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs256(std::string key)
				: hmacsha(std::move(key), EVP_sha256, "HS256")
			{}
		};
		/**
		 * HS384 algorithm
		 */
		struct hs384 : public hmacsha {
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs384(std::string key)
				: hmacsha(std::move(key), EVP_sha384, "HS384")
			{}
		};
		/**
		 * HS512 algorithm
		 */
		struct hs512 : public hmacsha {
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs512(std::string key)
				: hmacsha(std::move(key), EVP_sha512, "HS512")
			{}
		};
		/**
		 * RS256 algorithm
		 */
		struct rs256 : public rsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit rs256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "RS256")
			{}
		};
		/**
		 * RS384 algorithm
		 */
		struct rs384 : public rsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit rs384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "RS384")
			{}
		};
		/**
		 * RS512 algorithm
		 */
		struct rs512 : public rsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit rs512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "RS512")
			{}
		};
		/**
		 * ES256 algorithm
		 */
		struct es256 : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit es256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "ES256", 64)
			{}
		};
		/**
		 * ES384 algorithm
		 */
		struct es384 : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit es384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "ES384", 96)
			{}
		};
		/**
		 * ES512 algorithm
		 */
		struct es512 : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit es512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "ES512", 132)
			{}
		};

		/**
		 * PS256 algorithm
		 */
		struct ps256 : public pss {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit ps256(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "PS256")
			{}
		};
		/**
		 * PS384 algorithm
		 */
		struct ps384 : public pss {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit ps384(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "PS384")
			{}
		};
		/**
		 * PS512 algorithm
		 */
		struct ps512 : public pss {
			/**
			 * Construct new instance of algorithm
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit ps512(const std::string& public_key, const std::string& private_key = "", const std::string& public_key_password = "", const std::string& private_key_password = "")
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "PS512")
			{}
		};
	}  // namespace algorithm

	/**
	 * \brief JSON Abstractions for working with any library
	 */ 
	namespace json {
		/**
		 * \brief Generic JSON types used in JWTs
		 * 
		 * This enum is to abstract the third party underlying types
		 */
		enum class type {
			boolean,
			integer,
			number,
			string,
			array,
			object
		};
	}  // namespace json

	namespace details {
#ifdef __cpp_lib_void_t
		template <typename... Ts>
		using void_t = std::void_t<Ts...>;
#else
		// https://en.cppreference.com/w/cpp/types/void_t
		template <typename ...Ts>
		struct make_void
		{
			using type = void;
		};

		template <typename ...Ts>
		using void_t = typename make_void<Ts...>::type;
#endif

#ifdef __cpp_lib_experimental_detect
		template<template<typename...> class _Op, typename... _Args>
		using is_detected = std::experimental::is_detected<_Op, _Args...>;

		template<template<typename...> class _Op, typename... _Args>
		using is_detected_t = std::experimental::detected_t<_Op, _Args...>;
#else
		struct nonesuch
		{
			nonesuch() = delete;
			~nonesuch() = delete;
			nonesuch(nonesuch const&) = delete;
			nonesuch(nonesuch const&&) = delete;
			void operator=(nonesuch const&) = delete;
			void operator=(nonesuch&&) = delete;
		};

		// https://en.cppreference.com/w/cpp/experimental/is_detected
		template <class Default, class AlwaysVoid, template <class...> class Op, class... Args>
		struct detector
		{
			using value = std::false_type;
			using type = Default;
		};

		template <class Default, template <class...> class Op, class... Args>
		struct detector<Default, void_t<Op<Args...>>, Op, Args...>
		{
			using value = std::true_type;
			using type = Op<Args...>;
		};

		template <template <class...> class Op, class... Args>
		using is_detected = typename detector<nonesuch, void, Op, Args...>::value;

		template <template <class...> class Op, class... Args>
		using is_detected_t = typename detector<nonesuch, void, Op, Args...>::type;
#endif

		template <typename traits_type>
		using get_type_function = decltype(traits_type::get_type);

		template <typename traits_type, typename value_type>
		using is_get_type_signature = typename std::is_same<get_type_function<traits_type>, json::type(const value_type&)>;

		template <typename traits_type, typename value_type>
		struct supports_get_type {
			static constexpr auto value =
				is_detected<get_type_function, traits_type>::value && 
				std::is_function<get_type_function<traits_type>>::value &&
				is_get_type_signature<traits_type, value_type>::value;
		};

		template <typename traits_type>
		using as_object_function = decltype(traits_type::as_object);

		template <typename traits_type, typename value_type, typename object_type>
		using is_as_object_signature = typename std::is_same<as_object_function<traits_type>, object_type(const value_type&)>;

		template <typename traits_type, typename value_type, typename object_type>
		struct supports_as_object {
			static constexpr auto value =
			    std::is_constructible<value_type, object_type>::value &&
				is_detected<as_object_function, traits_type>::value &&
				std::is_function<as_object_function<traits_type>>::value &&
				is_as_object_signature<traits_type, value_type, object_type>::value;
		};

		template <typename traits_type>
		using as_array_function = decltype(traits_type::as_array);

		template <typename traits_type, typename value_type, typename array_type>
		using is_as_array_signature = typename std::is_same<as_array_function<traits_type>, array_type(const value_type&)>;

		template <typename traits_type, typename value_type, typename array_type>
		struct supports_as_array {
			static constexpr auto value =
			    std::is_constructible<value_type, array_type>::value &&
				is_detected<as_array_function, traits_type>::value &&
				std::is_function<as_array_function<traits_type>>::value &&
				is_as_array_signature<traits_type, value_type, array_type>::value;
		};

		template <typename traits_type>
		using as_string_function = decltype(traits_type::as_string);

		template <typename traits_type, typename value_type, typename string_type>
		using is_as_string_signature = typename std::is_same<as_string_function<traits_type>, string_type(const value_type&)>;

		template <typename traits_type, typename value_type, typename string_type>
		struct supports_as_string {
			static constexpr auto value =
			    std::is_constructible<value_type, string_type>::value &&
				is_detected<as_string_function, traits_type>::value &&
				std::is_function<as_string_function<traits_type>>::value &&
				is_as_string_signature<traits_type, value_type, string_type>::value;
		};

		template <typename traits_type>
		using as_number_function = decltype(traits_type::as_number);

		template <typename traits_type, typename value_type, typename number_type>
		using is_as_number_signature = typename std::is_same<as_number_function<traits_type>, number_type(const value_type&)>;

		template <typename traits_type, typename value_type, typename number_type>
		struct supports_as_number {
			static constexpr auto value =
				std::is_floating_point<number_type>::value &&
			    std::is_constructible<value_type, number_type>::value &&
				is_detected<as_number_function, traits_type>::value &&
				std::is_function<as_number_function<traits_type>>::value &&
				is_as_number_signature<traits_type, value_type, number_type>::value;
		};

		template <typename traits_type>
		using as_integer_function = decltype(traits_type::as_int);

		template <typename traits_type, typename value_type, typename integer_type>
		using is_as_integer_signature = typename std::is_same<as_integer_function<traits_type>, integer_type(const value_type&)>;

		template <typename traits_type, typename value_type, typename integer_type>
		struct supports_as_integer {
			static constexpr auto value =
				std::is_signed<integer_type>::value &&
				not std::is_floating_point<integer_type>::value &&
			    std::is_constructible<value_type, integer_type>::value &&
				is_detected<as_integer_function, traits_type>::value &&
				std::is_function<as_integer_function<traits_type>>::value &&
				is_as_integer_signature<traits_type, value_type, integer_type>::value;
		};

		template <typename traits_type>
		using as_boolean_function = decltype(traits_type::as_bool);

		template <typename traits_type, typename value_type, typename boolean_type>
		using is_as_boolean_signature = typename std::is_same<as_boolean_function<traits_type>, boolean_type(const value_type&)>;

		template <typename traits_type, typename value_type, typename boolean_type>
		struct supports_as_boolean {
			static constexpr auto value =
				std::is_convertible<boolean_type, bool>::value &&
			    std::is_constructible<value_type, boolean_type>::value &&
				is_detected<as_boolean_function, traits_type>::value &&
				std::is_function<as_boolean_function<traits_type>>::value &&
				is_as_boolean_signature<traits_type, value_type, boolean_type>::value;
		};

		template<typename traits>
		struct is_valid_traits {
			// Internal assertions for better feedback
			static_assert(supports_get_type<traits, typename traits::value_type>::value, "traits must provide `jwt::json::type get_type(const value_type&)`");
			static_assert(supports_as_object<traits, typename traits::value_type, typename traits::object_type>::value, "traits must provide `object_type as_object(const value_type&)`");
			static_assert(supports_as_array<traits, typename traits::value_type, typename traits::array_type>::value, "traits must provide `array_type as_array(const value_type&)`");
			static_assert(supports_as_string<traits, typename traits::value_type, typename traits::string_type>::value, "traits must provide `string_type as_string(const value_type&)`");
			static_assert(supports_as_number<traits, typename traits::value_type, typename traits::number_type>::value, "traits must provide `number_type as_number(const value_type&)`");
			static_assert(supports_as_integer<traits, typename traits::value_type, typename traits::integer_type>::value, "traits must provide `integer_type as_int(const value_type&)`");
			static_assert(supports_as_boolean<traits, typename traits::value_type, typename traits::boolean_type>::value, "traits must provide `boolean_type as_bool(const value_type&)`");

			static constexpr auto value =
				supports_get_type<traits, typename traits::value_type>::value &&
				supports_as_object<traits, typename traits::value_type, typename traits::object_type>::value &&
				supports_as_array<traits, typename traits::value_type, typename traits::array_type>::value &&
				supports_as_string<traits, typename traits::value_type, typename traits::string_type>::value &&
				supports_as_number<traits, typename traits::value_type, typename traits::number_type>::value &&
				supports_as_integer<traits, typename traits::value_type, typename traits::integer_type>::value &&
				supports_as_boolean<traits, typename traits::value_type, typename traits::boolean_type>::value;
		};

		template<typename value_type>
		struct is_valid_json_value {
			static constexpr auto value =
				std::is_default_constructible<value_type>::value &&
				std::is_constructible<value_type, const value_type&>::value && // a more generic is_copy_constructible
				std::is_move_constructible<value_type>::value &&
				std::is_assignable<value_type, value_type>::value &&
				std::is_copy_assignable<value_type>::value &&
				std::is_move_assignable<value_type>::value;
				// TODO(cmcarthur): Stream operators
		};

		template<typename value_type, typename string_type, typename object_type>
		struct is_valid_json_object {
			static constexpr auto value =
				std::is_same<typename object_type::mapped_type, value_type>::value &&
				std::is_same<typename object_type::key_type, string_type>::value;
		};

		template<typename value_type, typename array_type>
		struct is_valid_json_array {
			static constexpr auto value =
				std::is_same<typename array_type::value_type, value_type>::value;
		};

		template<typename value_type, typename string_type, typename object_type, typename array_type>
		struct is_valid_json_types {
			// Internal assertions for better feedback
			static_assert(is_valid_json_value<value_type>::value, "value type must meet basic requirements, default constructor, copyable, moveable");
			static_assert(is_valid_json_object<value_type, string_type, object_type>::value, "object_type must be a string_type to value_type container");
			static_assert(is_valid_json_array<value_type, array_type>::value, "array_type must be a container of value_type");
		
			static constexpr auto value =
				is_valid_json_object<value_type, string_type, object_type>::value &&
				is_valid_json_value<value_type>::value &&
				is_valid_json_array<value_type, array_type>::value;
		};
	}  // namespace details

	/**
	 * \brief a class to store a generic JSON value as claim
	 * 
	 * The default template parameters use [picojson](https://github.com/kazuho/picojson)
	 * 
	 * \tparam json_traits : JSON implementation traits
	 * 
	 * \see [RFC 7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
	 */
	template<typename json_traits>
	class basic_claim {
		/**
		 * The reason behind this is to provide an expressive abstraction without
		 * over complexifying the API. For more information take the time to read
		 * https://github.com/nlohmann/json/issues/774. It maybe be expanded to
		 * support custom string types.
		*/
		static_assert(std::is_same<typename json_traits::string_type, std::string>::value, "string_type must be a std::string.");

		static_assert(details::is_valid_json_types<
			typename json_traits::value_type,
			typename json_traits::string_type,
			typename json_traits::object_type,
			typename json_traits::array_type>::value, "must staisfy json container requirements");
		static_assert(details::is_valid_traits<json_traits>::value, "traits must satisfy requirements");

			typename json_traits::value_type val;
		public:
			using set_t = std::set<typename json_traits::string_type>;

			basic_claim() = default;
			basic_claim(const basic_claim&) = default;
			basic_claim(basic_claim&&) noexcept = default;
			basic_claim& operator=(const basic_claim&) = default;
			basic_claim& operator=(basic_claim&&) noexcept = default;
			~basic_claim() = default;

			JWT_CLAIM_EXPLICIT basic_claim(typename json_traits::string_type s)
				: val(std::move(s))
			{}
			JWT_CLAIM_EXPLICIT basic_claim(const date& d)
				: val(typename json_traits::integer_type(std::chrono::system_clock::to_time_t(d)))
			{}
			JWT_CLAIM_EXPLICIT basic_claim(typename json_traits::array_type a)
				: val(std::move(a))
			{}
			JWT_CLAIM_EXPLICIT basic_claim(typename json_traits::value_type v)
				: val(std::move(v))
			{}
			JWT_CLAIM_EXPLICIT basic_claim(const set_t& s)
				: val(typename json_traits::array_type(s.begin(), s.end()))
			{}
			template<typename Iterator>
			basic_claim(Iterator begin, Iterator end)
				: val(typename json_traits::array_type(begin, end))
			{}

			/**
			 * Get wrapped JSON value
			 * \return Wrapped JSON value
			 */
			typename json_traits::value_type to_json() const {
				return val;
			}

			/**
			 * Parse input stream into underlying JSON value
			 * \return input stream
			 */
			std::istream& operator>>(std::istream& is)
			{
				return is >> val;
			}

			/**
			 * Serialize claim to output stream from wrapped JSON value
			 * \return ouput stream
			 */
			std::ostream& operator<<(std::ostream& os)
			{
				return os << val;
			}

			/**
			 * Get type of contained JSON value
			 * \return Type
			 * \throw std::logic_error An internal error occured
			 */
			json::type get_type() const {
				return json_traits::get_type(val);
			}

			/**
			 * Get the contained JSON value as a string
			 * \return content as string
			 * \throw std::bad_cast Content was not a string
			 */
			typename json_traits::string_type as_string() const {
				return json_traits::as_string(val);
			}

			/**
			 * Get the contained JSON value as a date
			 * \return content as date
			 * \throw std::bad_cast Content was not a date
			 */
			date as_date() const {
				return std::chrono::system_clock::from_time_t(as_int());
			}

			/**
			 * Get the contained JSON value as an array
			 * \return content as array
			 * \throw std::bad_cast Content was not an array
			 */
			typename json_traits::array_type as_array() const {
				return json_traits::as_array(val);
			}

			/**
			 * Get the contained JSON value as a set of strings
			 * \return content as set of strings
			 * \throw std::bad_cast Content was not an array of string
			 */
			set_t as_set() const {
				set_t res;
				for(const auto& e : json_traits::as_array(val)) {
					res.insert(json_traits::as_string(e));
			}
				return res;
			}

			/**
			 * Get the contained JSON value as an integer
			 * \return content as int
			 * \throw std::bad_cast Content was not an int
			 */
			typename json_traits::integer_type as_int() const {
				return json_traits::as_int(val);
			}

			/**
			 * Get the contained JSON value as a bool
			 * \return content as bool
			 * \throw std::bad_cast Content was not a bool
			 */
			typename json_traits::boolean_type as_bool() const {
				return json_traits::as_bool(val);
			}

			/**
			 * Get the contained JSON value as a number
			 * \return content as double
			 * \throw std::bad_cast Content was not a number
			 */
			typename json_traits::number_type as_number() const {
				return json_traits::as_number(val);
			}
	};

	/**
	 * Base class that represents a token payload.
	 * Contains Convenience accessors for common claims.
	 */
	template<typename json_traits>
	class payload {
		using basic_claim_t = basic_claim<json_traits>;
	protected:
		std::unordered_map<typename json_traits::string_type, basic_claim_t> payload_claims;
	public:
		/**
		 * Check if issuer is present ("iss")
		 * \return true if present, false otherwise
		 */
		bool has_issuer() const noexcept { return has_payload_claim("iss"); }
		/**
		 * Check if subject is present ("sub")
		 * \return true if present, false otherwise
		 */
		bool has_subject() const noexcept { return has_payload_claim("sub"); }
		/**
		 * Check if audience is present ("aud")
		 * \return true if present, false otherwise
		 */
		bool has_audience() const noexcept { return has_payload_claim("aud"); }
		/**
		 * Check if expires is present ("exp")
		 * \return true if present, false otherwise
		 */
		bool has_expires_at() const noexcept { return has_payload_claim("exp"); }
		/**
		 * Check if not before is present ("nbf")
		 * \return true if present, false otherwise
		 */
		bool has_not_before() const noexcept { return has_payload_claim("nbf"); }
		/**
		 * Check if issued at is present ("iat")
		 * \return true if present, false otherwise
		 */
		bool has_issued_at() const noexcept { return has_payload_claim("iat"); }
		/**
		 * Check if token id is present ("jti")
		 * \return true if present, false otherwise
		 */
		bool has_id() const noexcept { return has_payload_claim("jti"); }
		/**
		 * Get issuer claim
		 * \return issuer as string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		typename json_traits::string_type get_issuer() const { return get_payload_claim("iss").as_string(); }
		/**
		 * Get subject claim
		 * \return subject as string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		typename json_traits::string_type get_subject() const { return get_payload_claim("sub").as_string(); }
		/**
		 * Get audience claim
		 * \return audience as a set of strings
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a set (Should not happen in a valid token)
		 */
		typename basic_claim_t::set_t get_audience() const { 
			auto aud = get_payload_claim("aud");
			if(aud.get_type() == json::type::string)
				return { aud.as_string() };
			
			return aud.as_set();
		}
		/**
		 * Get expires claim
		 * \return expires as a date in utc
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a date (Should not happen in a valid token)
		 */
		date get_expires_at() const { return get_payload_claim("exp").as_date(); }
		/**
		 * Get not valid before claim
		 * \return nbf date in utc
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a date (Should not happen in a valid token)
		 */
		date get_not_before() const { return get_payload_claim("nbf").as_date(); }
		/**
		 * Get issued at claim
		 * \return issued at as date in utc
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a date (Should not happen in a valid token)
		 */
		date get_issued_at() const { return get_payload_claim("iat").as_date(); }
		/**
		 * Get id claim
		 * \return id as string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		typename json_traits::string_type get_id() const { return get_payload_claim("jti").as_string(); }
		/**
		 * Check if a payload claim is present
		 * \return true if claim was present, false otherwise
		 */
		bool has_payload_claim(const typename json_traits::string_type& name) const noexcept { return payload_claims.count(name) != 0; }
		/**
		 * Get payload claim
		 * \return Requested claim
		 * \throw std::runtime_error If claim was not present
		 */
		basic_claim_t get_payload_claim(const typename json_traits::string_type& name) const {
			if (!has_payload_claim(name))
				throw std::runtime_error("claim not found");
			return payload_claims.at(name);
		}
	};

	/**
	 * Base class that represents a token header.
	 * Contains Convenience accessors for common claims.
	 */
	template<typename json_traits>
	class header {
		using basic_claim_t = basic_claim<json_traits>;
	protected:
		std::unordered_map<typename json_traits::string_type, basic_claim_t> header_claims;
	public:
		/**
		 * Check if algortihm is present ("alg")
		 * \return true if present, false otherwise
		 */
		bool has_algorithm() const noexcept { return has_header_claim("alg"); }
		/**
		 * Check if type is present ("typ")
		 * \return true if present, false otherwise
		 */
		bool has_type() const noexcept { return has_header_claim("typ"); }
		/**
		 * Check if content type is present ("cty")
		 * \return true if present, false otherwise
		 */
		bool has_content_type() const noexcept { return has_header_claim("cty"); }
		/**
		 * Check if key id is present ("kid")
		 * \return true if present, false otherwise
		 */
		bool has_key_id() const noexcept { return has_header_claim("kid"); }
		/**
		 * Get algorithm claim
		 * \return algorithm as string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		typename json_traits::string_type get_algorithm() const { return get_header_claim("alg").as_string(); }
		/**
		 * Get type claim
		 * \return type as a string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		typename json_traits::string_type get_type() const { return get_header_claim("typ").as_string(); }
		/**
		 * Get content type claim
		 * \return content type as string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		typename json_traits::string_type get_content_type() const { return get_header_claim("cty").as_string(); }
		/**
		 * Get key id claim
		 * \return key id as string
		 * \throw std::runtime_error If claim was not present
		 * \throw std::bad_cast Claim was present but not a string (Should not happen in a valid token)
		 */
		typename json_traits::string_type get_key_id() const { return get_header_claim("kid").as_string(); }
		/**
		 * Check if a header claim is present
		 * \return true if claim was present, false otherwise
		 */
		bool has_header_claim(const typename json_traits::string_type& name) const noexcept { return header_claims.count(name) != 0; }
		/**
		 * Get header claim
		 * \return Requested claim
		 * \throw std::runtime_error If claim was not present
		 */
		basic_claim_t get_header_claim(const typename json_traits::string_type& name) const {
			if (!has_header_claim(name))
				throw std::runtime_error("claim not found");
			return header_claims.at(name);
		}
	};

	/**
	 * Class containing all information about a decoded token
	 */
	template<typename json_traits>
	class decoded_jwt : public header<json_traits>, public payload<json_traits> {
	protected:
		/// Unmodifed token, as passed to constructor
		const typename json_traits::string_type token;
		/// Header part decoded from base64
		typename json_traits::string_type header;
		/// Unmodified header part in base64
		typename json_traits::string_type header_base64;
		/// Payload part decoded from base64
		typename json_traits::string_type payload;
		/// Unmodified payload part in base64
		typename json_traits::string_type payload_base64;
		/// Signature part decoded from base64
		typename json_traits::string_type signature;
		/// Unmodified signature part in base64
		typename json_traits::string_type signature_base64;
	public:
	#ifndef DISABLE_BASE64
		/**
		 * Constructor 
		 * Parses a given token
		 * Decodes using the jwt::base64url which supports an std::string
		 * \param token The token to parse
		 * \throw std::invalid_argument Token is not in correct format
		 * \throw std::runtime_error Base64 decoding failed or invalid json
		 */
		JWT_CLAIM_EXPLICIT decoded_jwt(const typename json_traits::string_type& token)
		: decoded_jwt(token, [](const typename json_traits::string_type& token){
				return base::decode<alphabet::base64url>(base::pad<alphabet::base64url>(token));
		})
		{}
	#endif
		/**
		 * Constructor 
		 * Parses a given token
		 * \tparam Decode is callabled, taking a string_type and returns a string_type.
		 * It should ensure the padding of the input and then base64url decode and 
		 * return the results.
		 * \param token The token to parse
		 * \param decode The token to parse
		 * \throw std::invalid_argument Token is not in correct format
		 * \throw std::runtime_error Base64 decoding failed or invalid json
		 */
		template<typename Decode>
		decoded_jwt(const typename json_traits::string_type& token, Decode decode)
			: token(token)
		{
			auto hdr_end = token.find('.');
			if (hdr_end == json_traits::string_type::npos)
				throw std::invalid_argument("invalid token supplied");
			auto payload_end = token.find('.', hdr_end + 1);
			if (payload_end == json_traits::string_type::npos)
				throw std::invalid_argument("invalid token supplied");
			header_base64 = token.substr(0, hdr_end);
			payload_base64 = token.substr(hdr_end + 1, payload_end - hdr_end - 1);
			signature_base64 = token.substr(payload_end + 1);

			header = decode(header_base64);
			payload = decode(payload_base64);
			signature = decode(signature_base64);

			auto parse_claims = [](const typename json_traits::string_type& str) {
				using basic_claim_t = basic_claim<json_traits>;
				std::unordered_map<typename json_traits::string_type, basic_claim_t> res;
				typename json_traits::value_type val;
				if (!json_traits::parse(val, str))
					throw std::runtime_error("Invalid json");

				for (const auto& e : json_traits::as_object(val)) {
					res.emplace(e.first, basic_claim_t(e.second));
				}

				return res;
			};

			this->header_claims = parse_claims(header);
			this->payload_claims = parse_claims(payload);
		}

		/**
		 * Get token string, as passed to constructor
		 * \return token as passed to constructor
		 */
		const typename json_traits::string_type& get_token() const noexcept { return token; }
		/**
		 * Get header part as json string
		 * \return header part after base64 decoding
		 */
		const typename json_traits::string_type& get_header() const noexcept { return header; }
		/**
		 * Get payload part as json string
		 * \return payload part after base64 decoding
		 */
		const typename json_traits::string_type& get_payload() const noexcept { return payload; }
		/**
		 * Get signature part as json string
		 * \return signature part after base64 decoding
		 */
		const typename json_traits::string_type& get_signature() const noexcept { return signature; }
		/**
		 * Get header part as base64 string
		 * \return header part before base64 decoding
		 */
		const typename json_traits::string_type& get_header_base64() const noexcept { return header_base64; }
		/**
		 * Get payload part as base64 string
		 * \return payload part before base64 decoding
		 */
		const typename json_traits::string_type& get_payload_base64() const noexcept { return payload_base64; }
		/**
		 * Get signature part as base64 string
		 * \return signature part before base64 decoding
		 */
		const typename json_traits::string_type& get_signature_base64() const noexcept { return signature_base64; }
		/**
		 * Get all payload claims
		 * \return map of claims
		 */
		std::unordered_map<typename json_traits::string_type, basic_claim<json_traits>> get_payload_claims() const {
			return this->payload_claims;
		}
		/**
		 * Get all header claims
		 * \return map of claims
		 */
		std::unordered_map<typename json_traits::string_type, basic_claim<json_traits>> get_header_claims() const {
			return this->header_claims;
		}
	};

	/**
	 * Builder class to build and sign a new token
	 * Use jwt::create() to get an instance of this class.
	 */
	template<typename json_traits>
	class builder {
		typename json_traits::object_type header_claims;
		typename json_traits::object_type payload_claims;
	public:
		builder() = default;
		/**
		 * Set a header claim.
		 * \param id Name of the claim
		 * \param c Claim to add
		 * \return *this to allow for method chaining
		 */
		builder& set_header_claim(const typename json_traits::string_type& id, typename json_traits::value_type c)
		{ header_claims[id] = std::move(c); return *this; }
		
		/**
		 * Set a header claim.
		 * \param id Name of the claim
		 * \param c Claim to add
		 * \return *this to allow for method chaining
		 */
		builder& set_header_claim(const typename json_traits::string_type& id, basic_claim<json_traits> c)
		{ header_claims[id] = c.to_json(); return *this; }
		/**
		 * Set a payload claim.
		 * \param id Name of the claim
		 * \param c Claim to add
		 * \return *this to allow for method chaining
		 */
		builder& set_payload_claim(const typename json_traits::string_type& id, typename json_traits::value_type c)
		{ payload_claims[id] = std::move(c); return *this; }
		/**
		 * Set a payload claim.
		 * \param id Name of the claim
		 * \param c Claim to add
		 * \return *this to allow for method chaining
		 */
		builder& set_payload_claim(const typename json_traits::string_type& id, basic_claim<json_traits> c)
		{ payload_claims[id] = c.to_json(); return *this; }
		/**
		 * Set algorithm claim
		 * You normally don't need to do this, as the algorithm is automatically set if you don't change it.
		 * \param str Name of algorithm
		 * \return *this to allow for method chaining
		 */
		builder& set_algorithm(typename json_traits::string_type str) { return set_header_claim("alg", typename json_traits::value_type(str)); }
		/**
		 * Set type claim
		 * \param str Type to set
		 * \return *this to allow for method chaining
		 */
		builder& set_type(typename json_traits::string_type str) { return set_header_claim("typ", typename json_traits::value_type(str)); }
		/**
		 * Set content type claim
		 * \param str Type to set
		 * \return *this to allow for method chaining
		 */
		builder& set_content_type(typename json_traits::string_type str) { return set_header_claim("cty", typename json_traits::value_type(str)); }
		/**
		 * Set key id claim
		 * \param str Key id to set
		 * \return *this to allow for method chaining
		 */
		builder& set_key_id(typename json_traits::string_type str) { return set_header_claim("kid", typename json_traits::value_type(str)); }
		/**
		 * Set issuer claim
		 * \param str Issuer to set
		 * \return *this to allow for method chaining
		 */
		builder& set_issuer(typename json_traits::string_type str) { return set_payload_claim("iss", typename json_traits::value_type(str)); }
		/**
		 * Set subject claim
		 * \param str Subject to set
		 * \return *this to allow for method chaining
		 */
		builder& set_subject(typename json_traits::string_type str) { return set_payload_claim("sub", typename json_traits::value_type(str)); }
		/**
		 * Set audience claim
		 * \param a Audience set
		 * \return *this to allow for method chaining
		 */
		builder& set_audience(typename json_traits::array_type a) { return set_payload_claim("aud", typename json_traits::value_type(a)); }
		/**
		 * Set audience claim
		 * \param aud Single audience
		 * \return *this to allow for method chaining
		 */
		builder& set_audience(typename json_traits::string_type aud) { return set_payload_claim("aud", typename json_traits::value_type(aud)); }
		/**
		 * Set expires at claim
		 * \param d Expires time
		 * \return *this to allow for method chaining
		 */
		builder& set_expires_at(const date& d) { return set_payload_claim("exp", basic_claim<json_traits>(d)); }
		/**
		 * Set not before claim
		 * \param d First valid time
		 * \return *this to allow for method chaining
		 */
		builder& set_not_before(const date& d) { return set_payload_claim("nbf", basic_claim<json_traits>(d)); }
		/**
		 * Set issued at claim
		 * \param d Issued at time, should be current time
		 * \return *this to allow for method chaining
		 */
		builder& set_issued_at(const date& d) { return set_payload_claim("iat", basic_claim<json_traits>(d)); }
		/**
		 * Set id claim
		 * \param str ID to set
		 * \return *this to allow for method chaining
		 */
		builder& set_id(const typename json_traits::string_type& str) { return set_payload_claim("jti", typename json_traits::value_type(str)); }

		/**
		 * Sign token and return result
		 * \tparam Algo Callable method which takes a string_type and return the signed input as a string_type
		 * \tparam Encode Callable method which takes a string_type and base64url safe encodes it,
		 * MUST return the result with no padding; trim the result.
		 * \param algo Instance of an algorithm to sign the token with
		 * \param encode Callable to transform the serialized json to base64 with no padding
		 * \return Final token as a string
		 * 
		 * \note If the 'alg' header in not set in the token it will be set to `algo.name()`
		 */
		template<typename Algo, typename Encode>
		typename json_traits::string_type sign(const Algo& algo, Encode encode) const {
			typename json_traits::object_type obj_header = header_claims;
			if(header_claims.count("alg") == 0)
				obj_header["alg"] = typename json_traits::value_type(algo.name());

			typename json_traits::string_type header = encode(json_traits::serialize(typename json_traits::value_type(obj_header)));
			typename json_traits::string_type payload = encode(json_traits::serialize(typename json_traits::value_type(payload_claims)));
			typename json_traits::string_type token = header + "." + payload;

			return token + "." + encode(algo.sign(token));
		}
	#ifndef DISABLE_BASE64
		/**
		 * Sign token and return result
		 * 
		 * using the `jwt::base` functions provided
		 * 
		 * \param algo Instance of an algorithm to sign the token with
		 * \return Final token as a string
		 */
		template<typename Algo>
		typename json_traits::string_type sign(const Algo& algo) const {
			return sign(algo, [](const typename json_traits::string_type& data) {
				return base::trim<alphabet::base64url>(base::encode<alphabet::base64url>(data));
			});
		}
	#endif
	};

	/**
	 * Verifier class used to check if a decoded token contains all claims required by your application and has a valid signature.
	 */
	template<typename Clock, typename json_traits>
	class verifier {
		struct algo_base {
			virtual ~algo_base() = default;
			virtual void verify(const std::string& data, const std::string& sig) = 0;
			virtual void verify(const std::string& data, const std::string& sig, std::error_code& ec) = 0;
		};
		template<typename T>
		struct algo : public algo_base {
			T alg;
			explicit algo(T a) : alg(a) {}
			void verify(const std::string& data, const std::string& sig) override {
				alg.verify(data, sig);
			}
			void verify(const std::string& data, const std::string& sig, std::error_code& ec) override {
				alg.verify(data, sig, ec);
			}
		};

		using basic_claim_t = basic_claim<json_traits>;
		/// Required claims
		std::unordered_map<typename json_traits::string_type, basic_claim_t> claims;
		/// Leeway time for exp, nbf and iat
		size_t default_leeway = 0;
		/// Instance of clock type
		Clock clock;
		/// Supported algorithms
		std::unordered_map<std::string, std::shared_ptr<algo_base>> algs;
	public:
		/**
		 * Constructor for building a new verifier instance
		 * \param c Clock instance
		 */
		explicit verifier(Clock c) : clock(c) {}

		/**
		 * Set default leeway to use.
		 * \param leeway Default leeway to use if not specified otherwise
		 * \return *this to allow chaining
		 */
		verifier& leeway(size_t leeway) { default_leeway = leeway; return *this; }
		/**
		 * Set leeway for expires at.
		 * If not specified the default leeway will be used.
		 * \param leeway Set leeway to use for expires at.
		 * \return *this to allow chaining
		 */
		verifier& expires_at_leeway(size_t leeway) { return with_claim("exp", basic_claim_t(std::chrono::system_clock::from_time_t(leeway))); }
		/**
		 * Set leeway for not before.
		 * If not specified the default leeway will be used.
		 * \param leeway Set leeway to use for not before.
		 * \return *this to allow chaining
		 */
		verifier& not_before_leeway(size_t leeway) { return with_claim("nbf", basic_claim_t(std::chrono::system_clock::from_time_t(leeway))); }
		/**
		 * Set leeway for issued at.
		 * If not specified the default leeway will be used.
		 * \param leeway Set leeway to use for issued at.
		 * \return *this to allow chaining
		 */
		verifier& issued_at_leeway(size_t leeway) { return with_claim("iat", basic_claim_t(std::chrono::system_clock::from_time_t(leeway))); }
		/**
		 * Set an issuer to check for.
		 * Check is casesensitive.
		 * \param iss Issuer to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_issuer(const typename json_traits::string_type& iss) { return with_claim("iss", basic_claim_t(iss)); }
		/**
		 * Set a subject to check for.
		 * Check is casesensitive.
		 * \param sub Subject to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_subject(const typename json_traits::string_type& sub) { return with_claim("sub", basic_claim_t(sub)); }
		/**
		 * Set an audience to check for.
		 * If any of the specified audiences is not present in the token the check fails.
		 * \param aud Audience to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_audience(const typename basic_claim_t::set_t& aud) { return with_claim("aud", basic_claim_t(aud)); }
		/**
		 * Set an audience to check for.
		 * If the specified audiences is not present in the token the check fails.
		 * \param aud Audience to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_audience(const typename json_traits::string_type& aud) { return with_claim("aud", basic_claim_t(aud)); }
		/**
		 * Set an id to check for.
		 * Check is casesensitive.
		 * \param id ID to check for.
		 * \return *this to allow chaining
		 */
		verifier& with_id(const typename json_traits::string_type& id) { return with_claim("jti", basic_claim_t(id)); }
		/**
		 * Specify a claim to check for.
		 * \param name Name of the claim to check for
		 * \param c Claim to check for
		 * \return *this to allow chaining
		 */
		verifier& with_claim(const typename json_traits::string_type& name, basic_claim_t c) { claims[name] = c; return *this; }

		/**
		 * Add an algorithm available for checking.
		 * \param alg Algorithm to allow
		 * \return *this to allow chaining
		 */
		template<typename Algorithm>
		verifier& allow_algorithm(Algorithm alg) {
			algs[alg.name()] = std::make_shared<algo<Algorithm>>(alg);
			return *this;
		}

		/**
		 * Verify the given token.
		 * \param jwt Token to check
		 * \throw token_verification_exception Verification failed
		 */
		void verify(const decoded_jwt<json_traits>& jwt) const {
			const typename json_traits::string_type data = jwt.get_header_base64() + "." + jwt.get_payload_base64();
			const typename json_traits::string_type sig = jwt.get_signature();
			const std::string algo = jwt.get_algorithm();
			if (algs.count(algo) == 0)
				throw token_verification_exception("wrong algorithm");
			algs.at(algo)->verify(data, sig);

			auto assert_claim_eq = [](const decoded_jwt<json_traits>& jwt, const typename json_traits::string_type& key, const basic_claim_t& c) {
				if (!jwt.has_payload_claim(key))
					throw token_verification_exception("decoded_jwt is missing " + key + " claim");
				auto jc = jwt.get_payload_claim(key);
				if (jc.get_type() != c.get_type())
					throw token_verification_exception("claim " + key + " type mismatch");
				if (c.get_type() == json::type::integer) {
					if (c.as_date() != jc.as_date())
						throw token_verification_exception("claim " + key + " does not match expected");
				}
				else if (c.get_type() == json::type::array) {
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
				else if (c.get_type() == json::type::object) {
					if (json_traits::serialize(c.to_json()) != json_traits::serialize(jc.to_json()))
						throw token_verification_exception("claim " + key + " does not match expected");
				}
				else if (c.get_type() == json::type::string) {
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

	/**
	 * Create a verifier using the given clock
	 * \param c Clock instance to use
	 * \return verifier instance
	 */
	template<typename Clock, typename json_traits>
	verifier<Clock, json_traits> verify(Clock c) {
		return verifier<Clock, json_traits>(c);
	}

	/**
	 * Default clock class using std::chrono::system_clock as a backend.
	 */
	struct default_clock {
		date now() const {
			return date::clock::now();
		}
	};

	/**
	 * Return a builder instance to create a new token
	 */
	template<typename json_traits>
	builder<json_traits> create() {
		return builder<json_traits>();
	}

	/**
	 * Decode a token
	 * \param token Token to decode
	 * \param decode function that will pad and base64url decode the token
	 * \return Decoded token
	 * \throw std::invalid_argument Token is not in correct format
	 * \throw std::runtime_error Base64 decoding failed or invalid json
	 */
	template<typename json_traits, typename Decode>
	decoded_jwt<json_traits> decode(const typename json_traits::string_type& token, Decode decode) {
		return decoded_jwt<json_traits>(token, decode);
	}

	/**
	 * Decode a token
	 * \param token Token to decode
	 * \return Decoded token
	 * \throw std::invalid_argument Token is not in correct format
	 * \throw std::runtime_error Base64 decoding failed or invalid json
	 */
	template<typename json_traits>
	decoded_jwt<json_traits> decode(const typename json_traits::string_type& token) {
		return decoded_jwt<json_traits>(token);
	}

#ifndef DISABLE_PICOJSON
	struct picojson_traits {
		using value_type = picojson::value;
		using object_type = picojson::object;
		using array_type = picojson::array;
		using string_type = std::string;
		using number_type = double;
		using integer_type = int64_t;
		using boolean_type = bool;

		static json::type get_type(const picojson::value& val) {
			using json::type;
			if (val.is<bool>()) return type::boolean;
			if (val.is<int64_t>()) return type::integer;
			if (val.is<double>()) return type::number;
			if (val.is<std::string>()) return type::string;
			if (val.is<picojson::array>()) return type::array;
			if (val.is<picojson::object>()) return type::object;

			throw std::logic_error("invalid type");
		}

		static picojson::object as_object(const picojson::value& val) {
			if (!val.is<picojson::object>())
				throw std::bad_cast();
			return val.get<picojson::object>();
		}

		static std::string as_string(const picojson::value& val) {
			if (!val.is<std::string>())
				throw std::bad_cast();
			return val.get<std::string>();
		}

		static picojson::array as_array(const picojson::value& val) {
			if (!val.is<picojson::array>())
				throw std::bad_cast();
			return val.get<picojson::array>();
		}

		static int64_t as_int(const picojson::value& val) {
			if (!val.is<int64_t>())
				throw std::bad_cast();
			return val.get<int64_t>();
		}

		static bool as_bool(const picojson::value& val) {
			if (!val.is<bool>())
				throw std::bad_cast();
			return val.get<bool>();
		}

		static double as_number(const picojson::value& val) {
			if (!val.is<double>())
				throw std::bad_cast();
			return val.get<double>();
		}

		static bool parse(picojson::value& val, const std::string& str){
			return picojson::parse(val, str).empty();
		}

		static std::string serialize(const picojson::value& val){
			return val.serialize();
		}
	};

	/**
	 * Default JSON claim
	 * 
	 * This type is the default specialization of the \ref basic_claim class which
	 * uses the standard template types.
	 */
	using claim = basic_claim<picojson_traits>;

	/**
	 * Create a verifier using the default clock
	 * \return verifier instance
	 */
	inline
	verifier<default_clock, picojson_traits> verify() {
		return verify<default_clock, picojson_traits>(default_clock{});
	}
	/**
	 * Return a picojson builder instance to create a new token
	 */
	inline
	builder<picojson_traits> create() {
		return builder<picojson_traits>();
	}

	/**
	 * Decode a token
	 * \param token Token to decode
	 * \return Decoded token
	 * \throw std::invalid_argument Token is not in correct format
	 * \throw std::runtime_error Base64 decoding failed or invalid json
	 */
	inline
	decoded_jwt<picojson_traits> decode(const std::string& token) {
		return decoded_jwt<picojson_traits>(token);
	}
#endif
}  // namespace jwt

template<typename json_traits>
std::istream& operator>>(std::istream& is, jwt::basic_claim<json_traits>& c)
{
	return c.operator>>(is);
}

template<typename json_traits>
std::ostream& operator<<(std::ostream& os, const jwt::basic_claim<json_traits>& c)
{
	return os << c.to_json();
}

#endif
