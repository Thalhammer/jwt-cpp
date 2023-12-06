#ifndef JWT_CPP_ALGORITHMS_H
#define JWT_CPP_ALGORITHMS_H

#include "errors.h"

#ifndef JWT_DISABLE_BASE64
#include "base.h"
#endif

#include <openssl/evp.h>
#include <openssl/opensslv.h>

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
			constexpr evp_pkey_handle() noexcept = default;
			explicit evp_pkey_handle(EVP_PKEY* key) noexcept {
#ifdef JWT_OPENSSL_1_0_0
				m_key = std::shared_ptr<EVP_PKEY>(key, EVP_PKEY_free);
#else
				m_key = key;
#endif
			}
			evp_pkey_handle(const evp_pkey_handle& other) = default;

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
			~evp_pkey_handle() noexcept { decrement_ref_count(m_key); }

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
	} // namespace helper
} // namespace jwt

#endif
