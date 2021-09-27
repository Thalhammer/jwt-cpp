#ifndef JWT_CPP_PICOJSON_DEFAULTS_H
#define JWT_CPP_PICOJSON_DEFAULTS_H

#include "traits.h"

namespace jwt {
	/**
	 * \brief a class to store a generic [picojson](https://github.com/kazuho/picojson) value as claim
	 *
	 * This type is the specialization of the \ref basic_claim class which
	 * uses the standard template types.
	 */
	using claim = basic_claim<picojson_traits>;

	/**
	 * Create a verifier using the default clock
	 * \return verifier instance
	 */
	inline verifier<default_clock, picojson_traits> verify() {
		return verify<default_clock, picojson_traits>(default_clock{});
	}

	/**
	 * Return a picojson builder instance to create a new token
	 */
	inline builder<picojson_traits> create() { return builder<picojson_traits>(); }

#ifndef JWT_DISABLE_BASE64
	/**
	 * Decode a token
	 * \param token Token to decode
	 * \return Decoded token
	 * \throw std::invalid_argument Token is not in correct format
	 * \throw std::runtime_error Base64 decoding failed or invalid json
	 */
	inline decoded_jwt<picojson_traits> decode(const std::string& token) { return decoded_jwt<picojson_traits>(token); }
#endif

	/**
	 * Decode a token
	 * \tparam Decode is callabled, taking a string_type and returns a string_type.
	 * It should ensure the padding of the input and then base64url decode and
	 * return the results.
	 * \param token Token to decode
	 * \param decode The token to parse
	 * \return Decoded token
	 * \throw std::invalid_argument Token is not in correct format
	 * \throw std::runtime_error Base64 decoding failed or invalid json
	 */
	template<typename Decode>
	decoded_jwt<picojson_traits> decode(const std::string& token, Decode decode) {
		return decoded_jwt<picojson_traits>(token, decode);
	}

	/**
	 * Parse a jwk
	 * \param token JWK Token to parse
	 * \return Parsed JWK
	 * \throw std::runtime_error Token is not in correct format
	 */
	inline jwk<picojson_traits> parse_jwk(const picojson_traits::string_type& token) {
		return jwk<picojson_traits>(token);
	}

	/**
	 * Parse a jwks
	 * \param token JWKs Token to parse
	 * \return Parsed JWKs
	 * \throw std::runtime_error Token is not in correct format
	 */
	inline jwks<picojson_traits> parse_jwks(const picojson_traits::string_type& token) {
		return jwks<picojson_traits>(token);
	}
} // namespace jwt

#endif // JWT_CPP_PICOJSON_DEFAULTS_H
