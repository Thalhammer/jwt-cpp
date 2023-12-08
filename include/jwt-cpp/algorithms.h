#ifndef JWT_CPP_ALGORITHMS_H
#define JWT_CPP_ALGORITHMS_H

#include "errors.h"

#ifndef JWT_DISABLE_BASE64
#include "base.h"
#endif

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include <string>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L // 3.0.0
#define JWT_OPENSSL_3_0
#elif OPENSSL_VERSION_NUMBER >= 0x10101000L // 1.1.1
#define JWT_OPENSSL_1_1_1
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L // 1.1.0
#define JWT_OPENSSL_1_1_0
#elif OPENSSL_VERSION_NUMBER >= 0x10000000L // 1.0.0
#define JWT_OPENSSL_1_0_0
#endif

#if defined(LIBRESSL_VERSION_NUMBER)
#if LIBRESSL_VERSION_NUMBER >= 0x3050300fL
#define JWT_OPENSSL_1_1_0
#else
#define JWT_OPENSSL_1_0_0
#endif
#endif

#if defined(LIBWOLFSSL_VERSION_HEX)
#define JWT_OPENSSL_1_1_1
#endif

#ifdef JWT_OPENSSL_1_0_0
#include <memory>
#else
#include <stdexcept>
#endif

namespace jwt {
	/**
	 * These _helpers_ are usefully when working with certificates OpenSSL APIs.
	 * For example, when dealing with JWKS (JSON Web Key Set)[https://tools.ietf.org/html/rfc7517]
	 * you maybe need to extract the modulus and exponent of an RSA Public Key.
	 */
	namespace helper {
		/** 
		 * \brief Handle class for EVP_PKEY structures
         * 
		 * Starting from OpenSSL 1.1.0, EVP_PKEY has internal reference counting. This handle class allows
		 * jwt-cpp to leverage that and thus safe an allocation for the control block in std::shared_ptr.
		 * The handle uses shared_ptr as a fallback on older versions. The behaviour should be identical between both.
         */
		class evp_pkey_handle {
		public:
			/// @brief Creates a null key pointer
			constexpr evp_pkey_handle() noexcept = default;
			/// @brief Creates a owning handle wrapper around an existing raw key
			/// @param key Existing key to reference count
			/// This does not increment the reference count
			explicit evp_pkey_handle(EVP_PKEY* key) noexcept {
#ifdef JWT_OPENSSL_1_0_0
				m_key = std::shared_ptr<EVP_PKEY>(key, EVP_PKEY_free);
#else
				m_key = key;
#endif
			}
			/// @brief Create a new handle incrementing the reference count
			/// @param other key pointer to copy and increase
			/// @throws std::runtime_error
			evp_pkey_handle(const evp_pkey_handle& other) : m_key{other.m_key} { increment_ref_count(m_key); }
			evp_pkey_handle(evp_pkey_handle&& other) noexcept : m_key{other.m_key} { other.m_key = nullptr; }
			~evp_pkey_handle() noexcept { decrement_ref_count(m_key); }

			EVP_PKEY* get() const noexcept {
#ifdef JWT_OPENSSL_1_0_0
				return m_key.get();
#else
				return m_key;
#endif
			}
			bool operator!() const noexcept { return m_key == nullptr; }
			explicit operator bool() const noexcept { return m_key != nullptr; }

			evp_pkey_handle& operator=(const evp_pkey_handle& other) {
				if (&other == this) return *this;
				decrement_ref_count(m_key);
				m_key = other.m_key;
				increment_ref_count(m_key);
				return *this;
			}
			evp_pkey_handle& operator=(evp_pkey_handle&& other) noexcept {
				if (&other == this) return *this;
				decrement_ref_count(m_key);
				m_key = other.m_key;
				other.m_key = nullptr;
				return *this;
			}
			evp_pkey_handle& operator=(EVP_PKEY* key) {
				decrement_ref_count(m_key);
				m_key = key;
				increment_ref_count(m_key);
				return *this;
			}

		private:
#ifdef JWT_OPENSSL_1_0_0
			std::shared_ptr<EVP_PKEY> m_key{nullptr};
#else
			EVP_PKEY* m_key{nullptr};
#endif

			static void increment_ref_count(EVP_PKEY* key) {
#ifdef JWT_OPENSSL_1_0_0
				return;
#else
				if (key != nullptr && EVP_PKEY_up_ref(key) != 1) throw std::runtime_error("EVP_PKEY_up_ref failed");
#endif
			}
			static void decrement_ref_count(EVP_PKEY* key) noexcept {
#ifdef JWT_OPENSSL_1_0_0
				return;
#else
				if (key != nullptr) EVP_PKEY_free(key);
#endif
			};
		};

		namespace details {
			inline std::unique_ptr<BIO, decltype(&BIO_free_all)> make_mem_buf_bio() {
				return std::unique_ptr<BIO, decltype(&BIO_free_all)>(BIO_new(BIO_s_mem()), BIO_free_all);
			}

			inline std::unique_ptr<BIO, decltype(&BIO_free_all)> make_mem_buf_bio(const std::string& data) {
				return std::unique_ptr<BIO, decltype(&BIO_free_all)>(
#if OPENSSL_VERSION_NUMBER <= 0x10100003L
					BIO_new_mem_buf(const_cast<char*>(data.data()), static_cast<int>(data.size())), BIO_free_all
#else
					BIO_new_mem_buf(data.data(), static_cast<int>(data.size())), BIO_free_all
#endif
				);
			}
		} // namespace details
		/**
		 * \brief Extract the public key of a PEM certificate
		 *
		 * \param certstr	String containing the certificate encoded as pem
		 * \param pw		Password used to decrypt certificate (leave empty if not encrypted)
		 * \param ec		error_code for error_detection (gets cleared if no error occurred)
		 */
		inline std::string extract_pubkey_from_cert(const std::string& certstr, const std::string& pw,
													std::error_code& ec) {
			ec.clear();
			auto certbio = details::make_mem_buf_bio(certstr);
			auto keybio = details::make_mem_buf_bio();
			if (!certbio || !keybio) {
				ec = error::rsa_error::create_mem_bio_failed;
				return {};
			}

			std::unique_ptr<X509, decltype(&X509_free)> cert(
				PEM_read_bio_X509(certbio.get(), nullptr, nullptr, const_cast<char*>(pw.c_str())), X509_free);
			if (!cert) {
				ec = error::rsa_error::cert_load_failed;
				return {};
			}
			std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(X509_get_pubkey(cert.get()), EVP_PKEY_free);
			if (!key) {
				ec = error::rsa_error::get_key_failed;
				return {};
			}
			if (PEM_write_bio_PUBKEY(keybio.get(), key.get()) == 0) {
				ec = error::rsa_error::write_key_failed;
				return {};
			}
			char* ptr = nullptr;
			auto len = BIO_get_mem_data(keybio.get(), &ptr);
			if (len <= 0 || ptr == nullptr) {
				ec = error::rsa_error::convert_to_pem_failed;
				return {};
			}
			return {ptr, static_cast<size_t>(len)};
		}

		/**
		 * \brief Extract the public key of a pem certificate
		 *
		 * \param certstr	String containing the certificate encoded as pem
		 * \param pw		Password used to decrypt certificate (leave empty if not encrypted)
		 * \throw			rsa_exception if an error occurred
		 */
		inline std::string extract_pubkey_from_cert(const std::string& certstr, const std::string& pw = "") {
			std::error_code ec;
			auto res = extract_pubkey_from_cert(certstr, pw, ec);
			error::throw_if_error(ec);
			return res;
		}

		/**
		 * \brief Convert the certificate provided as DER to PEM.
		 *
		 * \param cert_der_str 	String containing the certificate encoded as base64 DER
		 * \param ec			error_code for error_detection (gets cleared if no error occurs)
		 */
		inline std::string convert_der_to_pem(const std::string& cert_der_str, std::error_code& ec) {
			ec.clear();

			auto c_str = reinterpret_cast<const unsigned char*>(cert_der_str.c_str());

			std::unique_ptr<X509, decltype(&X509_free)> cert(
				d2i_X509(NULL, &c_str, static_cast<int>(cert_der_str.size())), X509_free);
			auto certbio = details::make_mem_buf_bio();
			if (!cert || !certbio) {
				ec = error::rsa_error::create_mem_bio_failed;
				return {};
			}

			if (!PEM_write_bio_X509(certbio.get(), cert.get())) {
				ec = error::rsa_error::write_cert_failed;
				return {};
			}

			char* ptr = nullptr;
			const auto len = BIO_get_mem_data(certbio.get(), &ptr);
			if (len <= 0 || ptr == nullptr) {
				ec = error::rsa_error::convert_to_pem_failed;
				return {};
			}

			return {ptr, static_cast<size_t>(len)};
		}

		/**
		 * \brief Convert the certificate provided as base64 DER to PEM.
		 *
		 * This is useful when using with JWKs as x5c claim is encoded as base64 DER. More info
		 * [here](https://tools.ietf.org/html/rfc7517#section-4.7).
		 *
		 * \tparam Decode is callable, taking a string_type and returns a string_type.
		 * It should ensure the padding of the input and then base64 decode and return
		 * the results.
		 *
		 * \param cert_base64_der_str 	String containing the certificate encoded as base64 DER
		 * \param decode 				The function to decode the cert
		 * \param ec					error_code for error_detection (gets cleared if no error occurs)
		 */
		template<typename Decode>
		std::string convert_base64_der_to_pem(const std::string& cert_base64_der_str, Decode decode,
											  std::error_code& ec) {
			ec.clear();
			const auto decoded_str = decode(cert_base64_der_str);
			return convert_der_to_pem(decoded_str, ec);
		}

		/**
		 * \brief Convert the certificate provided as base64 DER to PEM.
		 *
		 * This is useful when using with JWKs as x5c claim is encoded as base64 DER. More info
		 * [here](https://tools.ietf.org/html/rfc7517#section-4.7)
		 *
		 * \tparam Decode is callable, taking a string_type and returns a string_type.
		 * It should ensure the padding of the input and then base64 decode and return
		 * the results.
		 *
		 * \param cert_base64_der_str 	String containing the certificate encoded as base64 DER
		 * \param decode 				The function to decode the cert
		 * \throw						rsa_exception if an error occurred
		 */
		template<typename Decode>
		std::string convert_base64_der_to_pem(const std::string& cert_base64_der_str, Decode decode) {
			std::error_code ec;
			auto res = convert_base64_der_to_pem(cert_base64_der_str, std::move(decode), ec);
			error::throw_if_error(ec);
			return res;
		}

		/**
		 * \brief Convert the certificate provided as DER to PEM.
		 *
		 * \param cert_der_str 	String containing the DER certificate
		 * \throw				rsa_exception if an error occurred
		 */
		inline std::string convert_der_to_pem(const std::string& cert_der_str) {
			std::error_code ec;
			auto res = convert_der_to_pem(cert_der_str, ec);
			error::throw_if_error(ec);
			return res;
		}

#ifndef JWT_DISABLE_BASE64
		/**
		 * \brief Convert the certificate provided as base64 DER to PEM.
		 *
		 * This is useful when using with JWKs as x5c claim is encoded as base64 DER. More info
		 * [here](https://tools.ietf.org/html/rfc7517#section-4.7)
		 *
		 * \param cert_base64_der_str 	String containing the certificate encoded as base64 DER
		 * \param ec					error_code for error_detection (gets cleared if no error occurs)
		 */
		inline std::string convert_base64_der_to_pem(const std::string& cert_base64_der_str, std::error_code& ec) {
			auto decode = [](const std::string& token) {
				return base::decode<alphabet::base64>(base::pad<alphabet::base64>(token));
			};
			return convert_base64_der_to_pem(cert_base64_der_str, std::move(decode), ec);
		}

		/**
		 * \brief Convert the certificate provided as base64 DER to PEM.
		 *
		 * This is useful when using with JWKs as x5c claim is encoded as base64 DER. More info
		 * [here](https://tools.ietf.org/html/rfc7517#section-4.7)
		 *
		 * \param cert_base64_der_str 	String containing the certificate encoded as base64 DER
		 * \throw						rsa_exception if an error occurred
		 */
		inline std::string convert_base64_der_to_pem(const std::string& cert_base64_der_str) {
			std::error_code ec;
			auto res = convert_base64_der_to_pem(cert_base64_der_str, ec);
			error::throw_if_error(ec);
			return res;
		}
#endif
		/**
		 * \brief Load a public key from a string.
		 *
		 * The string should contain a pem encoded certificate or public key
		 *
		 * \param key		String containing the certificate encoded as pem
		 * \param password	Password used to decrypt certificate (leave empty if not encrypted)
		 * \param ec		error_code for error_detection (gets cleared if no error occurs)
		 */
		inline evp_pkey_handle load_public_key_from_string(const std::string& key, const std::string& password,
														   std::error_code& ec) {
			ec.clear();
			auto pubkey_bio = details::make_mem_buf_bio();
			if (!pubkey_bio) {
				ec = error::rsa_error::create_mem_bio_failed;
				return {};
			}
			if (key.substr(0, 27) == "-----BEGIN CERTIFICATE-----") {
				auto epkey = helper::extract_pubkey_from_cert(key, password, ec);
				if (ec) return {};
				const int len = static_cast<int>(epkey.size());
				if (BIO_write(pubkey_bio.get(), epkey.data(), len) != len) {
					ec = error::rsa_error::load_key_bio_write;
					return {};
				}
			} else {
				const int len = static_cast<int>(key.size());
				if (BIO_write(pubkey_bio.get(), key.data(), len) != len) {
					ec = error::rsa_error::load_key_bio_write;
					return {};
				}
			}

			evp_pkey_handle pkey(PEM_read_bio_PUBKEY(
				pubkey_bio.get(), nullptr, nullptr,
				(void*)password.data())); // NOLINT(google-readability-casting) requires `const_cast`
			if (!pkey) ec = error::rsa_error::load_key_bio_read;
			return pkey;
		}

		/**
		 * \brief Load a public key from a string.
		 *
		 * The string should contain a pem encoded certificate or public key
		 *
		 * \param key		String containing the certificate or key encoded as pem
		 * \param password	Password used to decrypt certificate or key (leave empty if not encrypted)
		 * \throw			rsa_exception if an error occurred
		 */
		inline evp_pkey_handle load_public_key_from_string(const std::string& key, const std::string& password = "") {
			std::error_code ec;
			auto res = load_public_key_from_string(key, password, ec);
			error::throw_if_error(ec);
			return res;
		}

		/**
		 * \brief Load a private key from a string.
		 *
		 * \param key		String containing a private key as pem
		 * \param password	Password used to decrypt key (leave empty if not encrypted)
		 * \param ec		error_code for error_detection (gets cleared if no error occurs)
		 */
		inline evp_pkey_handle load_private_key_from_string(const std::string& key, const std::string& password,
															std::error_code& ec) {
			auto privkey_bio = details::make_mem_buf_bio();
			if (!privkey_bio) {
				ec = error::rsa_error::create_mem_bio_failed;
				return {};
			}
			const int len = static_cast<int>(key.size());
			if (BIO_write(privkey_bio.get(), key.data(), len) != len) {
				ec = error::rsa_error::load_key_bio_write;
				return {};
			}
			evp_pkey_handle pkey(
				PEM_read_bio_PrivateKey(privkey_bio.get(), nullptr, nullptr, const_cast<char*>(password.c_str())));
			if (!pkey) ec = error::rsa_error::load_key_bio_read;
			return pkey;
		}

		/**
		 * \brief Load a private key from a string.
		 *
		 * \param key		String containing a private key as pem
		 * \param password	Password used to decrypt key (leave empty if not encrypted)
		 * \throw			rsa_exception if an error occurred
		 */
		inline evp_pkey_handle load_private_key_from_string(const std::string& key, const std::string& password = "") {
			std::error_code ec;
			auto res = load_private_key_from_string(key, password, ec);
			error::throw_if_error(ec);
			return res;
		}

		/**
		 * \brief Load a public key from a string.
		 *
		 * The string should contain a pem encoded certificate or public key
		 *
		 * \param key		String containing the certificate encoded as pem
		 * \param password	Password used to decrypt certificate (leave empty if not encrypted)
		 * \param ec		error_code for error_detection (gets cleared if no error occurs)
		 */
		inline evp_pkey_handle load_public_ec_key_from_string(const std::string& key, const std::string& password,
															  std::error_code& ec) {
			ec.clear();
			auto pubkey_bio = details::make_mem_buf_bio();
			if (!pubkey_bio) {
				ec = error::ecdsa_error::create_mem_bio_failed;
				return {};
			}
			if (key.substr(0, 27) == "-----BEGIN CERTIFICATE-----") {
				auto epkey = helper::extract_pubkey_from_cert(key, password, ec);
				if (ec) return {};
				const int len = static_cast<int>(epkey.size());
				if (BIO_write(pubkey_bio.get(), epkey.data(), len) != len) {
					ec = error::ecdsa_error::load_key_bio_write;
					return {};
				}
			} else {
				const int len = static_cast<int>(key.size());
				if (BIO_write(pubkey_bio.get(), key.data(), len) != len) {
					ec = error::ecdsa_error::load_key_bio_write;
					return {};
				}
			}

			evp_pkey_handle pkey(PEM_read_bio_PUBKEY(
				pubkey_bio.get(), nullptr, nullptr,
				(void*)password.data())); // NOLINT(google-readability-casting) requires `const_cast`
			if (!pkey) ec = error::ecdsa_error::load_key_bio_read;
			return pkey;
		}

		/**
		 * \brief Load a public key from a string.
		 *
		 * The string should contain a pem encoded certificate or public key
		 *
		 * \param key		String containing the certificate or key encoded as pem
		 * \param password	Password used to decrypt certificate or key (leave empty if not encrypted)
		 * \throw			ecdsa_exception if an error occurred
		 */
		inline evp_pkey_handle load_public_ec_key_from_string(const std::string& key,
															  const std::string& password = "") {
			std::error_code ec;
			auto res = load_public_ec_key_from_string(key, password, ec);
			error::throw_if_error(ec);
			return res;
		}

		/**
		 * \brief Load a private key from a string.
		 *
		 * \param key		String containing a private key as pem
		 * \param password	Password used to decrypt key (leave empty if not encrypted)
		 * \param ec		error_code for error_detection (gets cleared if no error occurs)
		 */
		inline evp_pkey_handle load_private_ec_key_from_string(const std::string& key, const std::string& password,
															   std::error_code& ec) {
			auto privkey_bio = details::make_mem_buf_bio();
			if (!privkey_bio) {
				ec = error::ecdsa_error::create_mem_bio_failed;
				return {};
			}
			const int len = static_cast<int>(key.size());
			if (BIO_write(privkey_bio.get(), key.data(), len) != len) {
				ec = error::ecdsa_error::load_key_bio_write;
				return {};
			}
			evp_pkey_handle pkey(
				PEM_read_bio_PrivateKey(privkey_bio.get(), nullptr, nullptr, const_cast<char*>(password.c_str())));
			if (!pkey) ec = error::ecdsa_error::load_key_bio_read;
			return pkey;
		}

		/**
		 * \brief Load a private key from a string.
		 *
		 * \param key		String containing a private key as pem
		 * \param password	Password used to decrypt key (leave empty if not encrypted)
		 * \throw			ecdsa_exception if an error occurred
		 */
		inline evp_pkey_handle load_private_ec_key_from_string(const std::string& key,
															   const std::string& password = "") {
			std::error_code ec;
			auto res = load_private_ec_key_from_string(key, password, ec);
			error::throw_if_error(ec);
			return res;
		}
	} // namespace helper

	namespace details {
		inline std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> make_evp_md_ctx() {
			return
#ifdef JWT_OPENSSL_1_0_0
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)>(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
#else
				std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
#endif
		}
		/**
		 * Convert a OpenSSL BIGNUM to a std::string
		 * \param bn BIGNUM to convert
		 * \return bignum as string
		 */
		inline std::string bn2raw(
#ifdef JWT_OPENSSL_1_0_0
			BIGNUM* bn)
#else
			const BIGNUM* bn)
#endif
		{
			std::string res(BN_num_bytes(bn), '\0');
			BN_bn2bin(bn, (unsigned char*)res.data()); // NOLINT(google-readability-casting) requires `const_cast`
			return res;
		}
		/**
		 * Convert an std::string to a OpenSSL BIGNUM
		 * \param raw String to convert
		 * \return BIGNUM representation
		 */
		inline std::unique_ptr<BIGNUM, decltype(&BN_free)> raw2bn(const std::string& raw) {
			return std::unique_ptr<BIGNUM, decltype(&BN_free)>(
				BN_bin2bn(reinterpret_cast<const unsigned char*>(raw.data()), static_cast<int>(raw.size()), nullptr),
				BN_free);
		}
	} // namespace details

	/**
	 * \brief Various cryptographic algorithms when working with JWT
	 *
	 * JWT (JSON Web Tokens) signatures are typically used as the payload for a JWS (JSON Web Signature) or
	 * JWE (JSON Web Encryption). Both of these use various cryptographic as specified by
	 * [RFC7518](https://tools.ietf.org/html/rfc7518) and are exposed through the a [JOSE
	 * Header](https://tools.ietf.org/html/rfc7515#section-4) which points to one of the JWA [JSON Web
	 * Algorithms](https://tools.ietf.org/html/rfc7518#section-3.1)
	 */
	namespace algorithm {
		/**
		 * \brief "none" algorithm.
		 *
		 * Returns and empty signature and checks if the given signature is empty.
		 * See [RFC 7518 Section 3.6](https://datatracker.ietf.org/doc/html/rfc7518#section-3.6)
		 * for more information.
		 */
		struct none {
			/**
			 * \brief Return an empty string
			 */
			std::string sign(const std::string& /*unused*/, std::error_code& ec) const {
				ec.clear();
				return {};
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
				if (!signature.empty()) { ec = error::signature_verification_error::invalid_signature; }
			}
			/// Get algorithm name
			std::string name() const { return "none"; }
		};
		/**
		 * \brief Base class for HMAC family of algorithms
		 */
		struct hmacsha {
			/**
			 * Construct new hmac algorithm
			 * 
			 * \param key Key to use for HMAC
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			hmacsha(std::string key, const EVP_MD* (*md)(), std::string name)
				: secret(std::move(key)), md(md), alg_name(std::move(name)) {}
			/**
			 * Sign jwt data
			 * 
			 * \param data The data to sign
			 * \param ec error_code filled with details on error
			 * \return HMAC signature for the given data
			 */
			std::string sign(const std::string& data, std::error_code& ec) const {
				ec.clear();
				std::string res(static_cast<size_t>(EVP_MAX_MD_SIZE), '\0');
				auto len = static_cast<unsigned int>(res.size());
				if (HMAC(md(), secret.data(), static_cast<int>(secret.size()),
						 reinterpret_cast<const unsigned char*>(data.data()), static_cast<int>(data.size()),
						 (unsigned char*)res.data(), // NOLINT(google-readability-casting) requires `const_cast`
						 &len) == nullptr) {
					ec = error::signature_generation_error::hmac_failed;
					return {};
				}
				res.resize(len);
				return res;
			}
			/**
			 * Check if signature is valid
			 * 
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec Filled with details about failure.
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
				ec.clear();
				auto res = sign(data, ec);
				if (ec) return;

				bool matched = true;
				for (size_t i = 0; i < std::min<size_t>(res.size(), signature.size()); i++)
					if (res[i] != signature[i]) matched = false;
				if (res.size() != signature.size()) matched = false;
				if (!matched) {
					ec = error::signature_verification_error::invalid_signature;
					return;
				}
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * 
			 * \return algorithm's name
			 */
			std::string name() const { return alg_name; }

		private:
			/// HMAC secret
			const std::string secret;
			/// HMAC hash generator
			const EVP_MD* (*md)();
			/// algorithm's name
			const std::string alg_name;
		};
		/**
		 * \brief Base class for RSA family of algorithms
		 */
		struct rsa {
			/**
			 * Construct new rsa algorithm
			 * 
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 */
			rsa(const std::string& public_key, const std::string& private_key, const std::string& public_key_password,
				const std::string& private_key_password, const EVP_MD* (*md)(), std::string name)
				: md(md), alg_name(std::move(name)) {
				if (!private_key.empty()) {
					pkey = helper::load_private_key_from_string(private_key, private_key_password);
				} else if (!public_key.empty()) {
					pkey = helper::load_public_key_from_string(public_key, public_key_password);
				} else
					throw error::rsa_exception(error::rsa_error::no_key_provided);
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \param ec error_code filled with details on error
			 * \return RSA signature for the given data
			 */
			std::string sign(const std::string& data, std::error_code& ec) const {
				ec.clear();
				auto ctx = details::make_evp_md_ctx();
				if (!ctx) {
					ec = error::signature_generation_error::create_context_failed;
					return {};
				}
				if (!EVP_SignInit(ctx.get(), md())) {
					ec = error::signature_generation_error::signinit_failed;
					return {};
				}

				std::string res(EVP_PKEY_size(pkey.get()), '\0');
				unsigned int len = 0;

				if (!EVP_SignUpdate(ctx.get(), data.data(), data.size())) {
					ec = error::signature_generation_error::signupdate_failed;
					return {};
				}
				if (EVP_SignFinal(ctx.get(), (unsigned char*)res.data(), &len, pkey.get()) == 0) {
					ec = error::signature_generation_error::signfinal_failed;
					return {};
				}

				res.resize(len);
				return res;
			}
			/**
			 * Check if signature is valid
			 * 
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec Filled with details on failure
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
				ec.clear();
				auto ctx = details::make_evp_md_ctx();
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
				auto res = EVP_VerifyFinal(ctx.get(), reinterpret_cast<const unsigned char*>(signature.data()),
										   static_cast<unsigned int>(signature.size()), pkey.get());
				if (res != 1) {
					ec = error::signature_verification_error::verifyfinal_failed;
					return;
				}
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return algorithm's name
			 */
			std::string name() const { return alg_name; }

		private:
			/// OpenSSL structure containing converted keys
			helper::evp_pkey_handle pkey;
			/// Hash generator
			const EVP_MD* (*md)();
			/// algorithm's name
			const std::string alg_name;
		};
		/**
		 * \brief Base class for ECDSA family of algorithms
		 */
		struct ecdsa {
			/**
			 * Construct new ecdsa algorithm
			 *
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always fail
			 * \param public_key_password Password to decrypt public key pem
			 * \param private_key_password Password to decrypt private key pem
			 * \param md Pointer to hash function
			 * \param name Name of the algorithm
			 * \param siglen The bit length of the signature
			 */
			ecdsa(const std::string& public_key, const std::string& private_key, const std::string& public_key_password,
				  const std::string& private_key_password, const EVP_MD* (*md)(), std::string name, size_t siglen)
				: md(md), alg_name(std::move(name)), signature_length(siglen) {
				if (!private_key.empty()) {
					pkey = helper::load_private_ec_key_from_string(private_key, private_key_password);
					check_private_key(pkey.get());
				} else if (!public_key.empty()) {
					pkey = helper::load_public_ec_key_from_string(public_key, public_key_password);
					check_public_key(pkey.get());
				} else {
					throw error::ecdsa_exception(error::ecdsa_error::no_key_provided);
				}
				if (!pkey) throw error::ecdsa_exception(error::ecdsa_error::invalid_key);

				size_t keysize = EVP_PKEY_bits(pkey.get());
				if (keysize != signature_length * 4 && (signature_length != 132 || keysize != 521))
					throw error::ecdsa_exception(error::ecdsa_error::invalid_key_size);
			}

			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \param ec error_code filled with details on error
			 * \return ECDSA signature for the given data
			 */
			std::string sign(const std::string& data, std::error_code& ec) const {
				ec.clear();
				auto ctx = details::make_evp_md_ctx();
				if (!ctx) {
					ec = error::signature_generation_error::create_context_failed;
					return {};
				}
				if (!EVP_DigestSignInit(ctx.get(), nullptr, md(), nullptr, pkey.get())) {
					ec = error::signature_generation_error::signinit_failed;
					return {};
				}
				if (!EVP_DigestUpdate(ctx.get(), data.data(), data.size())) {
					ec = error::signature_generation_error::digestupdate_failed;
					return {};
				}

				size_t len = 0;
				if (!EVP_DigestSignFinal(ctx.get(), nullptr, &len)) {
					ec = error::signature_generation_error::signfinal_failed;
					return {};
				}
				std::string res(len, '\0');
				if (!EVP_DigestSignFinal(ctx.get(), (unsigned char*)res.data(), &len)) {
					ec = error::signature_generation_error::signfinal_failed;
					return {};
				}

				res.resize(len);
				return der_to_p1363_signature(res, ec);
			}

			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec Filled with details on error
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
				ec.clear();
				std::string der_signature = p1363_to_der_signature(signature, ec);
				if (ec) { return; }

				auto ctx = details::make_evp_md_ctx();
				if (!ctx) {
					ec = error::signature_verification_error::create_context_failed;
					return;
				}
				if (!EVP_DigestVerifyInit(ctx.get(), nullptr, md(), nullptr, pkey.get())) {
					ec = error::signature_verification_error::verifyinit_failed;
					return;
				}
				if (!EVP_DigestUpdate(ctx.get(), data.data(), data.size())) {
					ec = error::signature_verification_error::verifyupdate_failed;
					return;
				}

#if OPENSSL_VERSION_NUMBER < 0x10002000L
				unsigned char* der_sig_data = reinterpret_cast<unsigned char*>(const_cast<char*>(der_signature.data()));
#else
				const unsigned char* der_sig_data = reinterpret_cast<const unsigned char*>(der_signature.data());
#endif
				auto res =
					EVP_DigestVerifyFinal(ctx.get(), der_sig_data, static_cast<unsigned int>(der_signature.length()));
				if (res == 0) {
					ec = error::signature_verification_error::invalid_signature;
					return;
				}
				if (res == -1) {
					ec = error::signature_verification_error::verifyfinal_failed;
					return;
				}
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return algorithm's name
			 */
			std::string name() const { return alg_name; }

		private:
			static void check_public_key(EVP_PKEY* pkey) {
#ifdef JWT_OPENSSL_3_0
				std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
					EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr), EVP_PKEY_CTX_free);
				if (!ctx) { throw error::ecdsa_exception(error::ecdsa_error::create_context_failed); }
				if (EVP_PKEY_public_check(ctx.get()) != 1) {
					throw error::ecdsa_exception(error::ecdsa_error::invalid_key);
				}
#else
				std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> eckey(EVP_PKEY_get1_EC_KEY(pkey), EC_KEY_free);
				if (!eckey) { throw error::ecdsa_exception(error::ecdsa_error::invalid_key); }
				if (EC_KEY_check_key(eckey.get()) == 0) throw error::ecdsa_exception(error::ecdsa_error::invalid_key);
#endif
			}

			static void check_private_key(EVP_PKEY* pkey) {
#ifdef JWT_OPENSSL_3_0
				std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
					EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr), EVP_PKEY_CTX_free);
				if (!ctx) { throw error::ecdsa_exception(error::ecdsa_error::create_context_failed); }
				if (EVP_PKEY_private_check(ctx.get()) != 1) {
					throw error::ecdsa_exception(error::ecdsa_error::invalid_key);
				}
#else
				std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> eckey(EVP_PKEY_get1_EC_KEY(pkey), EC_KEY_free);
				if (!eckey) { throw error::ecdsa_exception(error::ecdsa_error::invalid_key); }
				if (EC_KEY_check_key(eckey.get()) == 0) throw error::ecdsa_exception(error::ecdsa_error::invalid_key);
#endif
			}

			std::string der_to_p1363_signature(const std::string& der_signature, std::error_code& ec) const {
				const unsigned char* possl_signature = reinterpret_cast<const unsigned char*>(der_signature.data());
				std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
					d2i_ECDSA_SIG(nullptr, &possl_signature, static_cast<long>(der_signature.length())),
					ECDSA_SIG_free);
				if (!sig) {
					ec = error::signature_generation_error::signature_decoding_failed;
					return {};
				}

#ifdef JWT_OPENSSL_1_0_0

				auto rr = details::bn2raw(sig->r);
				auto rs = details::bn2raw(sig->s);
#else
				const BIGNUM* r;
				const BIGNUM* s;
				ECDSA_SIG_get0(sig.get(), &r, &s);
				auto rr = details::bn2raw(r);
				auto rs = details::bn2raw(s);
#endif
				if (rr.size() > signature_length / 2 || rs.size() > signature_length / 2)
					throw std::logic_error("bignum size exceeded expected length");
				rr.insert(0, signature_length / 2 - rr.size(), '\0');
				rs.insert(0, signature_length / 2 - rs.size(), '\0');
				return rr + rs;
			}

			std::string p1363_to_der_signature(const std::string& signature, std::error_code& ec) const {
				ec.clear();
				auto r = details::raw2bn(signature.substr(0, signature.size() / 2));
				auto s = details::raw2bn(signature.substr(signature.size() / 2));

				ECDSA_SIG* psig;
#ifdef JWT_OPENSSL_1_0_0
				ECDSA_SIG sig;
				sig.r = r.get();
				sig.s = s.get();
				psig = &sig;
#else
				std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(ECDSA_SIG_new(), ECDSA_SIG_free);
				if (!sig) {
					ec = error::signature_verification_error::create_context_failed;
					return {};
				}
				ECDSA_SIG_set0(sig.get(), r.release(), s.release());
				psig = sig.get();
#endif

				int length = i2d_ECDSA_SIG(psig, nullptr);
				if (length < 0) {
					ec = error::signature_verification_error::signature_encoding_failed;
					return {};
				}
				std::string der_signature(length, '\0');
				unsigned char* psbuffer = (unsigned char*)der_signature.data();
				length = i2d_ECDSA_SIG(psig, &psbuffer);
				if (length < 0) {
					ec = error::signature_verification_error::signature_encoding_failed;
					return {};
				}
				der_signature.resize(length);
				return der_signature;
			}

			/// OpenSSL struct containing keys
			helper::evp_pkey_handle pkey;
			/// Hash generator function
			const EVP_MD* (*md)();
			/// algorithm's name
			const std::string alg_name;
			/// Length of the resulting signature
			const size_t signature_length;
		};

#if !defined(JWT_OPENSSL_1_0_0) && !defined(JWT_OPENSSL_1_1_0)
		/**
		 * \brief Base class for EdDSA family of algorithms
		 *
		 * https://tools.ietf.org/html/rfc8032
		 *
		 * The EdDSA algorithms were introduced in [OpenSSL v1.1.1](https://www.openssl.org/news/openssl-1.1.1-notes.html),
		 * so these algorithms are only available when building against this version or higher.
		 */
		struct eddsa {
			/**
			 * Construct new eddsa algorithm
			 * \param public_key EdDSA public key in PEM format
			 * \param private_key EdDSA private key or empty string if not available. If empty, signing will always
			 * fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password
			 * to decrypt private key pem.
			 * \param name Name of the algorithm
			 */
			eddsa(const std::string& public_key, const std::string& private_key, const std::string& public_key_password,
				  const std::string& private_key_password, std::string name)
				: alg_name(std::move(name)) {
				if (!private_key.empty()) {
					pkey = helper::load_private_key_from_string(private_key, private_key_password);
				} else if (!public_key.empty()) {
					pkey = helper::load_public_key_from_string(public_key, public_key_password);
				} else
					throw error::ecdsa_exception(error::ecdsa_error::load_key_bio_read);
			}
			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \param ec error_code filled with details on error
			 * \return EdDSA signature for the given data
			 */
			std::string sign(const std::string& data, std::error_code& ec) const {
				ec.clear();
				auto ctx = details::make_evp_md_ctx();
				if (!ctx) {
					ec = error::signature_generation_error::create_context_failed;
					return {};
				}
				if (!EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get())) {
					ec = error::signature_generation_error::signinit_failed;
					return {};
				}

				size_t len = EVP_PKEY_size(pkey.get());
				std::string res(len, '\0');

// LibreSSL is the special kid in the block, as it does not support EVP_DigestSign.
// OpenSSL on the otherhand does not support using EVP_DigestSignUpdate for eddsa, which is why we end up with this
// mess.
#if defined(LIBRESSL_VERSION_NUMBER) || defined(LIBWOLFSSL_VERSION_HEX)
				ERR_clear_error();
				if (EVP_DigestSignUpdate(ctx.get(), reinterpret_cast<const unsigned char*>(data.data()), data.size()) !=
					1) {
					std::cout << ERR_error_string(ERR_get_error(), NULL) << std::endl;
					ec = error::signature_generation_error::signupdate_failed;
					return {};
				}
				if (EVP_DigestSignFinal(ctx.get(), reinterpret_cast<unsigned char*>(&res[0]), &len) != 1) {
					ec = error::signature_generation_error::signfinal_failed;
					return {};
				}
#else
				if (EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(&res[0]), &len,
								   reinterpret_cast<const unsigned char*>(data.data()), data.size()) != 1) {
					ec = error::signature_generation_error::signfinal_failed;
					return {};
				}
#endif

				res.resize(len);
				return res;
			}

			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec Filled with details on error
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
				ec.clear();
				auto ctx = details::make_evp_md_ctx();
				if (!ctx) {
					ec = error::signature_verification_error::create_context_failed;
					return;
				}
				if (!EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get())) {
					ec = error::signature_verification_error::verifyinit_failed;
					return;
				}
// LibreSSL is the special kid in the block, as it does not support EVP_DigestVerify.
// OpenSSL on the otherhand does not support using EVP_DigestVerifyUpdate for eddsa, which is why we end up with this
// mess.
#if defined(LIBRESSL_VERSION_NUMBER) || defined(LIBWOLFSSL_VERSION_HEX)
				if (EVP_DigestVerifyUpdate(ctx.get(), reinterpret_cast<const unsigned char*>(data.data()),
										   data.size()) != 1) {
					ec = error::signature_verification_error::verifyupdate_failed;
					return;
				}
				if (EVP_DigestVerifyFinal(ctx.get(), reinterpret_cast<const unsigned char*>(signature.data()),
										  signature.size()) != 1) {
					ec = error::signature_verification_error::verifyfinal_failed;
					return;
				}
#else
				auto res = EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char*>(signature.data()),
											signature.size(), reinterpret_cast<const unsigned char*>(data.data()),
											data.size());
				if (res != 1) {
					ec = error::signature_verification_error::verifyfinal_failed;
					return;
				}
#endif
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return algorithm's name
			 */
			std::string name() const { return alg_name; }

		private:
			/// OpenSSL struct containing keys
			helper::evp_pkey_handle pkey;
			/// algorithm's name
			const std::string alg_name;
		};
#endif
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
			pss(const std::string& public_key, const std::string& private_key, const std::string& public_key_password,
				const std::string& private_key_password, const EVP_MD* (*md)(), std::string name)
				: md(md), alg_name(std::move(name)) {
				if (!private_key.empty()) {
					pkey = helper::load_private_key_from_string(private_key, private_key_password);
				} else if (!public_key.empty()) {
					pkey = helper::load_public_key_from_string(public_key, public_key_password);
				} else
					throw error::rsa_exception(error::rsa_error::no_key_provided);
			}

			/**
			 * Sign jwt data
			 * \param data The data to sign
			 * \param ec error_code filled with details on error
			 * \return ECDSA signature for the given data
			 */
			std::string sign(const std::string& data, std::error_code& ec) const {
				ec.clear();
				auto md_ctx = details::make_evp_md_ctx();
				if (!md_ctx) {
					ec = error::signature_generation_error::create_context_failed;
					return {};
				}
				EVP_PKEY_CTX* ctx = nullptr;
				if (EVP_DigestSignInit(md_ctx.get(), &ctx, md(), nullptr, pkey.get()) != 1) {
					ec = error::signature_generation_error::signinit_failed;
					return {};
				}
				if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
					ec = error::signature_generation_error::rsa_padding_failed;
					return {};
				}
// wolfSSL does not require EVP_PKEY_CTX_set_rsa_pss_saltlen. The default behavior
// sets the salt length to the hash length. Unlike OpenSSL which exposes this functionality.
#ifndef LIBWOLFSSL_VERSION_HEX
				if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -1) <= 0) {
					ec = error::signature_generation_error::set_rsa_pss_saltlen_failed;
					return {};
				}
#endif
				if (EVP_DigestUpdate(md_ctx.get(), data.data(), data.size()) != 1) {
					ec = error::signature_generation_error::digestupdate_failed;
					return {};
				}

				size_t size = EVP_PKEY_size(pkey.get());
				std::string res(size, 0x00);
				if (EVP_DigestSignFinal(
						md_ctx.get(),
						(unsigned char*)res.data(), // NOLINT(google-readability-casting) requires `const_cast`
						&size) <= 0) {
					ec = error::signature_generation_error::signfinal_failed;
					return {};
				}

				return res;
			}

			/**
			 * Check if signature is valid
			 * \param data The data to check signature against
			 * \param signature Signature provided by the jwt
			 * \param ec Filled with error details
			 */
			void verify(const std::string& data, const std::string& signature, std::error_code& ec) const {
				ec.clear();

				auto md_ctx = details::make_evp_md_ctx();
				if (!md_ctx) {
					ec = error::signature_verification_error::create_context_failed;
					return;
				}
				EVP_PKEY_CTX* ctx = nullptr;
				if (EVP_DigestVerifyInit(md_ctx.get(), &ctx, md(), nullptr, pkey.get()) != 1) {
					ec = error::signature_verification_error::verifyinit_failed;
					return;
				}
				if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
					ec = error::signature_generation_error::rsa_padding_failed;
					return;
				}
// wolfSSL does not require EVP_PKEY_CTX_set_rsa_pss_saltlen. The default behavior
// sets the salt length to the hash length. Unlike OpenSSL which exposes this functionality.
#ifndef LIBWOLFSSL_VERSION_HEX
				if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -1) <= 0) {
					ec = error::signature_verification_error::set_rsa_pss_saltlen_failed;
					return;
				}
#endif
				if (EVP_DigestUpdate(md_ctx.get(), data.data(), data.size()) != 1) {
					ec = error::signature_verification_error::verifyupdate_failed;
					return;
				}

				if (EVP_DigestVerifyFinal(md_ctx.get(), (unsigned char*)signature.data(), signature.size()) <= 0) {
					ec = error::signature_verification_error::verifyfinal_failed;
					return;
				}
			}
			/**
			 * Returns the algorithm name provided to the constructor
			 * \return algorithm's name
			 */
			std::string name() const { return alg_name; }

		private:
			/// OpenSSL structure containing keys
			helper::evp_pkey_handle pkey;
			/// Hash generator function
			const EVP_MD* (*md)();
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
			explicit hs256(std::string key) : hmacsha(std::move(key), EVP_sha256, "HS256") {}
		};
		/**
		 * HS384 algorithm
		 */
		struct hs384 : public hmacsha {
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs384(std::string key) : hmacsha(std::move(key), EVP_sha384, "HS384") {}
		};
		/**
		 * HS512 algorithm
		 */
		struct hs512 : public hmacsha {
			/**
			 * Construct new instance of algorithm
			 * \param key HMAC signing key
			 */
			explicit hs512(std::string key) : hmacsha(std::move(key), EVP_sha512, "HS512") {}
		};
		/**
		 * RS256 algorithm
		 */
		struct rs256 : public rsa {
			/**
			 * \brief Construct new instance of algorithm
             * 
			 * \param public_key RSA public key in PEM format
			 * \param private_key RSA private key or empty string if not available. If empty, signing will always fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
             * 
             * This data structure is used to describe the RSA256 and can be used to verify JWTs
			 */
			explicit rs256(const std::string& public_key, const std::string& private_key = "",
						   const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "RS256") {}
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
			explicit rs384(const std::string& public_key, const std::string& private_key = "",
						   const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "RS384") {}
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
			explicit rs512(const std::string& public_key, const std::string& private_key = "",
						   const std::string& public_key_password = "", const std::string& private_key_password = "")
				: rsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "RS512") {}
		};
		/**
		 * ES256 algorithm
		 */
		struct es256 : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always
			 * fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password
			 * to decrypt private key pem.
			 */
			explicit es256(const std::string& public_key, const std::string& private_key = "",
						   const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "ES256", 64) {}
		};
		/**
		 * ES384 algorithm
		 */
		struct es384 : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always
			 * fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password
			 * to decrypt private key pem.
			 */
			explicit es384(const std::string& public_key, const std::string& private_key = "",
						   const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "ES384", 96) {}
		};
		/**
		 * ES512 algorithm
		 */
		struct es512 : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always
			 * fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password
			 * to decrypt private key pem.
			 */
			explicit es512(const std::string& public_key, const std::string& private_key = "",
						   const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "ES512", 132) {}
		};
		/**
		 * ES256K algorithm
		 */
		struct es256k : public ecdsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key ECDSA public key in PEM format
			 * \param private_key ECDSA private key or empty string if not available. If empty, signing will always
			 * fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password to decrypt private key pem.
			 */
			explicit es256k(const std::string& public_key, const std::string& private_key = "",
							const std::string& public_key_password = "", const std::string& private_key_password = "")
				: ecdsa(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "ES256K", 64) {}
		};

#if !defined(JWT_OPENSSL_1_0_0) && !defined(JWT_OPENSSL_1_1_0)
		/**
		 * Ed25519 algorithm
		 *
		 * https://en.wikipedia.org/wiki/EdDSA#Ed25519
		 *
		 * Requires at least OpenSSL 1.1.1.
		 */
		struct ed25519 : public eddsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key Ed25519 public key in PEM format
			 * \param private_key Ed25519 private key or empty string if not available. If empty, signing will always
			 * fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password
			 * to decrypt private key pem.
			 */
			explicit ed25519(const std::string& public_key, const std::string& private_key = "",
							 const std::string& public_key_password = "", const std::string& private_key_password = "")
				: eddsa(public_key, private_key, public_key_password, private_key_password, "EdDSA") {}
		};

		/**
		 * Ed448 algorithm
		 *
		 * https://en.wikipedia.org/wiki/EdDSA#Ed448
		 *
		 * Requires at least OpenSSL 1.1.1.
		 */
		struct ed448 : public eddsa {
			/**
			 * Construct new instance of algorithm
			 * \param public_key Ed448 public key in PEM format
			 * \param private_key Ed448 private key or empty string if not available. If empty, signing will always
			 * fail.
			 * \param public_key_password Password to decrypt public key pem.
			 * \param private_key_password Password
			 * to decrypt private key pem.
			 */
			explicit ed448(const std::string& public_key, const std::string& private_key = "",
						   const std::string& public_key_password = "", const std::string& private_key_password = "")
				: eddsa(public_key, private_key, public_key_password, private_key_password, "EdDSA") {}
		};
#endif

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
			explicit ps256(const std::string& public_key, const std::string& private_key = "",
						   const std::string& public_key_password = "", const std::string& private_key_password = "")
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha256, "PS256") {}
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
			explicit ps384(const std::string& public_key, const std::string& private_key = "",
						   const std::string& public_key_password = "", const std::string& private_key_password = "")
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha384, "PS384") {}
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
			explicit ps512(const std::string& public_key, const std::string& private_key = "",
						   const std::string& public_key_password = "", const std::string& private_key_password = "")
				: pss(public_key, private_key, public_key_password, private_key_password, EVP_sha512, "PS512") {}
		};
	} // namespace algorithm
} // namespace jwt

#endif
