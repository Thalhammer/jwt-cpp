#ifndef JWT_CPP_ERRORS_H
#define JWT_CPP_ERRORS_H

#include <system_error>

namespace jwt {
	/**
	 * \brief Everything related to error codes issued by the library
	 */
	namespace error {
		struct signature_verification_exception : public std::system_error {
			using system_error::system_error;
		};
		struct signature_generation_exception : public std::system_error {
			using system_error::system_error;
		};
		struct rsa_exception : public std::system_error {
			using system_error::system_error;
		};
		struct ecdsa_exception : public std::system_error {
			using system_error::system_error;
		};
		struct token_verification_exception : public std::system_error {
			using system_error::system_error;
		};
		/**
		 * \brief Errors related to processing of RSA signatures
		 */
		enum class rsa_error {
			ok = 0,
			cert_load_failed = 10,
			get_key_failed,
			write_key_failed,
			write_cert_failed,
			convert_to_pem_failed,
			load_key_bio_write,
			load_key_bio_read,
			create_mem_bio_failed,
			no_key_provided
		};
		/**
		 * \brief Error category for RSA errors
		 */
		inline std::error_category& rsa_error_category() {
			class rsa_error_cat : public std::error_category {
			public:
				const char* name() const noexcept override { return "rsa_error"; };
				std::string message(int ev) const override {
					switch (static_cast<rsa_error>(ev)) {
					case rsa_error::ok: return "no error";
					case rsa_error::cert_load_failed: return "error loading cert into memory";
					case rsa_error::get_key_failed: return "error getting key from certificate";
					case rsa_error::write_key_failed: return "error writing key data in PEM format";
					case rsa_error::write_cert_failed: return "error writing cert data in PEM format";
					case rsa_error::convert_to_pem_failed: return "failed to convert key to pem";
					case rsa_error::load_key_bio_write: return "failed to load key: bio write failed";
					case rsa_error::load_key_bio_read: return "failed to load key: bio read failed";
					case rsa_error::create_mem_bio_failed: return "failed to create memory bio";
					case rsa_error::no_key_provided: return "at least one of public or private key need to be present";
					default: return "unknown RSA error";
					}
				}
			};
			static rsa_error_cat cat;
			return cat;
		}

		inline std::error_code make_error_code(rsa_error e) { return {static_cast<int>(e), rsa_error_category()}; }
		/**
		 * \brief Errors related to processing of RSA signatures
		 */
		enum class ecdsa_error {
			ok = 0,
			load_key_bio_write = 10,
			load_key_bio_read,
			create_mem_bio_failed,
			no_key_provided,
			invalid_key_size,
			invalid_key,
			create_context_failed
		};
		/**
		 * \brief Error category for ECDSA errors
		 */
		inline std::error_category& ecdsa_error_category() {
			class ecdsa_error_cat : public std::error_category {
			public:
				const char* name() const noexcept override { return "ecdsa_error"; };
				std::string message(int ev) const override {
					switch (static_cast<ecdsa_error>(ev)) {
					case ecdsa_error::ok: return "no error";
					case ecdsa_error::load_key_bio_write: return "failed to load key: bio write failed";
					case ecdsa_error::load_key_bio_read: return "failed to load key: bio read failed";
					case ecdsa_error::create_mem_bio_failed: return "failed to create memory bio";
					case ecdsa_error::no_key_provided:
						return "at least one of public or private key need to be present";
					case ecdsa_error::invalid_key_size: return "invalid key size";
					case ecdsa_error::invalid_key: return "invalid key";
					case ecdsa_error::create_context_failed: return "failed to create context";
					default: return "unknown ECDSA error";
					}
				}
			};
			static ecdsa_error_cat cat;
			return cat;
		}

		inline std::error_code make_error_code(ecdsa_error e) { return {static_cast<int>(e), ecdsa_error_category()}; }

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
			get_key_failed,
			set_rsa_pss_saltlen_failed,
			signature_encoding_failed
		};
		/**
		 * \brief Error category for verification errors
		 */
		inline std::error_category& signature_verification_error_category() {
			class verification_error_cat : public std::error_category {
			public:
				const char* name() const noexcept override { return "signature_verification_error"; };
				std::string message(int ev) const override {
					switch (static_cast<signature_verification_error>(ev)) {
					case signature_verification_error::ok: return "no error";
					case signature_verification_error::invalid_signature: return "invalid signature";
					case signature_verification_error::create_context_failed:
						return "failed to verify signature: could not create context";
					case signature_verification_error::verifyinit_failed:
						return "failed to verify signature: VerifyInit failed";
					case signature_verification_error::verifyupdate_failed:
						return "failed to verify signature: VerifyUpdate failed";
					case signature_verification_error::verifyfinal_failed:
						return "failed to verify signature: VerifyFinal failed";
					case signature_verification_error::get_key_failed:
						return "failed to verify signature: Could not get key";
					case signature_verification_error::set_rsa_pss_saltlen_failed:
						return "failed to verify signature: EVP_PKEY_CTX_set_rsa_pss_saltlen failed";
					case signature_verification_error::signature_encoding_failed:
						return "failed to verify signature: i2d_ECDSA_SIG failed";
					default: return "unknown signature verification error";
					}
				}
			};
			static verification_error_cat cat;
			return cat;
		}

		inline std::error_code make_error_code(signature_verification_error e) {
			return {static_cast<int>(e), signature_verification_error_category()};
		}

		/**
		 * \brief Errors related to signature generation errors
		 */
		enum class signature_generation_error {
			ok = 0,
			hmac_failed = 10,
			create_context_failed,
			signinit_failed,
			signupdate_failed,
			signfinal_failed,
			ecdsa_do_sign_failed,
			digestinit_failed,
			digestupdate_failed,
			digestfinal_failed,
			rsa_padding_failed,
			rsa_private_encrypt_failed,
			get_key_failed,
			set_rsa_pss_saltlen_failed,
			signature_decoding_failed
		};
		/**
		 * \brief Error category for signature generation errors
		 */
		inline std::error_category& signature_generation_error_category() {
			class signature_generation_error_cat : public std::error_category {
			public:
				const char* name() const noexcept override { return "signature_generation_error"; };
				std::string message(int ev) const override {
					switch (static_cast<signature_generation_error>(ev)) {
					case signature_generation_error::ok: return "no error";
					case signature_generation_error::hmac_failed: return "hmac failed";
					case signature_generation_error::create_context_failed:
						return "failed to create signature: could not create context";
					case signature_generation_error::signinit_failed:
						return "failed to create signature: SignInit failed";
					case signature_generation_error::signupdate_failed:
						return "failed to create signature: SignUpdate failed";
					case signature_generation_error::signfinal_failed:
						return "failed to create signature: SignFinal failed";
					case signature_generation_error::ecdsa_do_sign_failed: return "failed to generate ecdsa signature";
					case signature_generation_error::digestinit_failed:
						return "failed to create signature: DigestInit failed";
					case signature_generation_error::digestupdate_failed:
						return "failed to create signature: DigestUpdate failed";
					case signature_generation_error::digestfinal_failed:
						return "failed to create signature: DigestFinal failed";
					case signature_generation_error::rsa_padding_failed:
						return "failed to create signature: EVP_PKEY_CTX_set_rsa_padding failed";
					case signature_generation_error::rsa_private_encrypt_failed:
						return "failed to create signature: RSA_private_encrypt failed";
					case signature_generation_error::get_key_failed:
						return "failed to generate signature: Could not get key";
					case signature_generation_error::set_rsa_pss_saltlen_failed:
						return "failed to create signature: EVP_PKEY_CTX_set_rsa_pss_saltlen failed";
					case signature_generation_error::signature_decoding_failed:
						return "failed to create signature: d2i_ECDSA_SIG failed";
					default: return "unknown signature generation error";
					}
				}
			};
			static signature_generation_error_cat cat = {};
			return cat;
		}

		inline std::error_code make_error_code(signature_generation_error e) {
			return {static_cast<int>(e), signature_generation_error_category()};
		}

		/**
		 * \brief Errors related to token verification errors
		 */
		enum class token_verification_error {
			ok = 0,
			wrong_algorithm = 10,
			missing_claim,
			claim_type_missmatch,
			claim_value_missmatch,
			token_expired,
			audience_missmatch
		};
		/**
		 * \brief Error category for token verification errors
		 */
		inline std::error_category& token_verification_error_category() {
			class token_verification_error_cat : public std::error_category {
			public:
				const char* name() const noexcept override { return "token_verification_error"; };
				std::string message(int ev) const override {
					switch (static_cast<token_verification_error>(ev)) {
					case token_verification_error::ok: return "no error";
					case token_verification_error::wrong_algorithm: return "wrong algorithm";
					case token_verification_error::missing_claim: return "decoded JWT is missing required claim(s)";
					case token_verification_error::claim_type_missmatch:
						return "claim type does not match expected type";
					case token_verification_error::claim_value_missmatch:
						return "claim value does not match expected value";
					case token_verification_error::token_expired: return "token expired";
					case token_verification_error::audience_missmatch:
						return "token doesn't contain the required audience";
					default: return "unknown token verification error";
					}
				}
			};
			static token_verification_error_cat cat = {};
			return cat;
		}

		inline std::error_code make_error_code(token_verification_error e) {
			return {static_cast<int>(e), token_verification_error_category()};
		}

		inline void throw_if_error(std::error_code ec) {
			if (ec) {
				if (ec.category() == rsa_error_category()) throw rsa_exception(ec);
				if (ec.category() == ecdsa_error_category()) throw ecdsa_exception(ec);
				if (ec.category() == signature_verification_error_category())
					throw signature_verification_exception(ec);
				if (ec.category() == signature_generation_error_category()) throw signature_generation_exception(ec);
				if (ec.category() == token_verification_error_category()) throw token_verification_exception(ec);
			}
		}
	} // namespace error
} // namespace jwt

namespace std {
	template<>
	struct is_error_code_enum<jwt::error::rsa_error> : true_type {};
	template<>
	struct is_error_code_enum<jwt::error::ecdsa_error> : true_type {};
	template<>
	struct is_error_code_enum<jwt::error::signature_verification_error> : true_type {};
	template<>
	struct is_error_code_enum<jwt::error::signature_generation_error> : true_type {};
	template<>
	struct is_error_code_enum<jwt::error::token_verification_error> : true_type {};
} // namespace std

#endif
