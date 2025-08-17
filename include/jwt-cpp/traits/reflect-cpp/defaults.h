#pragma once

#ifndef JWT_DISABLE_PICOJSON
#define JWT_DISABLE_PICOJSON
#endif

#include "traits.h"

namespace jwt {

	/**
         * \brief a class to store a generic reflect-cpp (rfl::Generic) value as claim
         *
         * This type is the specialization of the \ref basic_claim class which
         * uses the reflect-cpp JSON traits.
         */
	using claim = basic_claim<traits::reflect_cpp>;

	/** Create a verifier using the default clock */
	inline verifier<default_clock, traits::reflect_cpp> verify() {
		return verify<default_clock, traits::reflect_cpp>(default_clock{});
	}

	/** Create a builder using the default clock */
	inline builder<default_clock, traits::reflect_cpp> create() {
		return builder<default_clock, traits::reflect_cpp>(default_clock{});
	}

#ifndef JWT_DISABLE_BASE64
	/** Decode a token (uses jwt-cpp’s built-in base64 if not disabled) */
	inline decoded_jwt<traits::reflect_cpp> decode(const std::string& token) {
		return decoded_jwt<traits::reflect_cpp>(token);
	}
#endif

	template<typename Decode>
	decoded_jwt<traits::reflect_cpp> decode(const std::string& token, Decode decode) {
		return decoded_jwt<traits::reflect_cpp>(token, decode);
	}

	/** Parse a JWK */
	inline jwk<traits::reflect_cpp> parse_jwk(const traits::reflect_cpp::string_type& token) {
		return jwk<traits::reflect_cpp>(token);
	}

	/** Parse a JWKS */
	inline jwks<traits::reflect_cpp> parse_jwks(const traits::reflect_cpp::string_type& token) {
		return jwks<traits::reflect_cpp>(token);
	}

	/** Verify context type alias (for advanced verification ops) */
	using verify_context = verify_ops::verify_context<traits::reflect_cpp>;

} // namespace jwt
