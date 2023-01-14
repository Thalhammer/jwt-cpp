#ifndef JWT_CPP_BASE_H
#define JWT_CPP_BASE_H

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>

#include "string_types.h"

#ifdef __has_cpp_attribute
#if __has_cpp_attribute(fallthrough)
#define JWT_FALLTHROUGH [[fallthrough]]
#endif
#endif

#ifndef JWT_FALLTHROUGH
#define JWT_FALLTHROUGH
#endif

#ifndef JWT_HAS_STRING_VIEW
#include <array>
#include <cstring>
#endif

namespace jwt {
	/**
	 * \brief character maps when encoding and decoding
	 */
	namespace alphabet {
		/**
		 * \brief valid list of character when working with [Base64](https://datatracker.ietf.org/doc/html/rfc4648#section-4)
		 *
		 * As directed in [X.509 Parameter](https://datatracker.ietf.org/doc/html/rfc7517#section-4.7) certificate chains are
		 * base64-encoded as per [Section 4 of RFC4648](https://datatracker.ietf.org/doc/html/rfc4648#section-4)
		 */
		struct base64 {

#define JWT_BASE_ALPHABET                                                                                              \
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', \
		'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',  \
		't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'

#ifdef JWT_HAS_STRING_VIEW
			// From C++17 it's perfectly fine to have inline static variables. No ODR violation in this case.
			static constexpr char kData[]{JWT_BASE_ALPHABET, '+', '/'};

			static constexpr std::string_view kFill[]{"="};
#else
			// For pre C++17 standards, we need to use a method
			static const std::array<char, 64>& data() {
				static constexpr std::array<char, 64> kData{{JWT_BASE_ALPHABET, '+', '/'}};
				return kData;
			}

			static const std::array<const char*, 1>& fill() {
				static constexpr std::array<const char*, 1> kFill{"="};
				return kFill;
			}
#endif
		};

		/**
		 * \brief valid list of character when working with [Base64URL](https://tools.ietf.org/html/rfc4648#section-5)
		 *
		 * As directed by [RFC 7519 Terminology](https://datatracker.ietf.org/doc/html/rfc7519#section-2) set the definition of Base64URL
		 * encoding as that in [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515#section-2) that states:
		 *
		 * > Base64 encoding using the URL- and filename-safe character set defined in
		 * > [Section 5 of RFC 4648 RFC4648](https://tools.ietf.org/html/rfc4648#section-5), with all trailing '=' characters omitted
		 */
		struct base64url {

#ifdef JWT_HAS_STRING_VIEW
			static constexpr char kData[]{JWT_BASE_ALPHABET, '-', '_'};

			static constexpr std::string_view kFill[]{"%3d"};
#else
			// For pre C++17 standards, we need to use a method
			static const std::array<char, 64>& data() {
				static constexpr std::array<char, 64> kData{{JWT_BASE_ALPHABET, '-', '_'}};
				return kData;
			}

			static const std::array<const char*, 1>& fill() {
				static constexpr std::array<const char*, 1> kFill{"%3d"};
				return kFill;
			}

#endif
		};
		namespace helper {
			/**
			 * @brief A General purpose base64url alphabet respecting the
			 * [URI Case Normalization](https://datatracker.ietf.org/doc/html/rfc3986#section-6.2.2.1)
			 *
			 * This is useful in situations outside of JWT encoding/decoding and is provided as a helper
			 */
			struct base64url_percent_encoding {

#ifdef JWT_HAS_STRING_VIEW
				static constexpr char kData[]{JWT_BASE_ALPHABET, '-', '_'};

				static constexpr std::string_view kFill[]{"%3D", "%3d"};
#else
				// For pre C++17 standards, we need to use a method
				static const std::array<char, 64>& data() {
					static constexpr std::array<char, 64> kData{{JWT_BASE_ALPHABET, '-', '_'}};
					return kData;
				}

				static const std::array<const char*, 2>& fill() {
					static constexpr std::array<const char*, 2> kFill{"%3D", "%3d"};
					return kFill;
				}
#endif
			};
		} // namespace helper

		template<class char_it>
		inline uint32_t index(char_it alphabetBeg, char_it alphabetEnd, char symbol) {
			if (symbol >= 'A' && symbol <= 'Z') { return static_cast<uint32_t>(symbol - 'A'); }
			if (symbol >= 'a' && symbol <= 'z') { return static_cast<uint32_t>(26 + symbol - 'a'); }
			if (symbol >= '0' && symbol <= '9') { return static_cast<uint32_t>(52 + symbol - '0'); }
			auto itr = std::find(std::next(alphabetBeg, 62U), alphabetEnd, symbol);
			if (itr == alphabetEnd) { throw std::runtime_error("Invalid input: not within alphabet"); }

			return static_cast<uint32_t>(std::distance(alphabetBeg, itr));
		}
	} // namespace alphabet

	/**
	 * \brief A collection of fellable functions for working with base64 and base64url
	 */
	namespace base {

		namespace details {
			struct padding {
				size_t count = 0;
				size_t length = 0;

				padding() = default;

				padding(size_t c, size_t l) : count(c), length(l) {}

				padding operator+(const padding& p) const { return padding{count + p.count, length + p.length}; }
			};

			inline std::size_t string_len(string_view str) { return str.size(); }

			template<class str_input_it>
			padding count_padding(string_view base, str_input_it fillStart, str_input_it fillEnd) {
				for (str_input_it fillIt = fillStart; fillIt != fillEnd; ++fillIt) {
					std::size_t fillLen = string_len(*fillIt);
					if (base.size() >= fillLen) {
						std::size_t deltaLen = base.size() - fillLen;
						// Does the end of the input exactly match the fill pattern?
						if (base.substr(deltaLen) == *fillIt) {
							return padding{1UL, fillLen} + count_padding(base.substr(0, deltaLen), fillStart, fillEnd);
						}
					}
				}

				return {};
			}

			inline std::string encode(string_view bin, const char* alphabet, string_view fill) {
				size_t size = bin.size();
				std::string res;

				res.reserve((4UL * size) / 3UL);

				// clear incomplete bytes
				size_t mod = size % 3;

				size_t fast_size = size - mod;
				for (size_t i = 0; i < fast_size; i += 3) {
					uint32_t octet_a = static_cast<unsigned char>(bin[i]);
					uint32_t octet_b = static_cast<unsigned char>(bin[i + 1]);
					uint32_t octet_c = static_cast<unsigned char>(bin[i + 2]);

					uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

					res += alphabet[(triple >> 3 * 6) & 0x3F];
					res += alphabet[(triple >> 2 * 6) & 0x3F];
					res += alphabet[(triple >> 1 * 6) & 0x3F];
					res += alphabet[(triple >> 0 * 6) & 0x3F];
				}

				if (fast_size == size) return res;

				uint32_t octet_a = fast_size < size ? static_cast<unsigned char>(bin[fast_size++]) : 0;
				uint32_t octet_b = fast_size < size ? static_cast<unsigned char>(bin[fast_size++]) : 0;
				uint32_t octet_c = fast_size < size ? static_cast<unsigned char>(bin[fast_size++]) : 0;

				uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

				switch (mod) {
				case 1:
					res += alphabet[(triple >> 3 * 6) & 0x3F];
					res += alphabet[(triple >> 2 * 6) & 0x3F];
					res += fill;
					res += fill;
					break;
				case 2:
					res += alphabet[(triple >> 3 * 6) & 0x3F];
					res += alphabet[(triple >> 2 * 6) & 0x3F];
					res += alphabet[(triple >> 1 * 6) & 0x3F];
					res += fill;
					break;
				default: break;
				}

				return res;
			}

			template<class char_it, class str_input_it>
			inline std::string decode(string_view base, char_it alphabetBeg, char_it alphabetEnd,
									  str_input_it fillStart, str_input_it fillEnd) {
				const auto pad = count_padding(base, fillStart, fillEnd);
				if (pad.count > 2) throw std::runtime_error("Invalid input: too much fill");

				const size_t size = base.size() - pad.length;
				if ((size + pad.count) % 4 != 0) throw std::runtime_error("Invalid input: incorrect total size");

				size_t out_size = size / 4 * 3;
				std::string res;
				res.reserve(out_size);

				auto get_sextet = [&](size_t offset) {
					return alphabet::index(alphabetBeg, alphabetEnd, base[offset]);
				};

				size_t fast_size = size - size % 4;
				for (size_t i = 0; i < fast_size;) {
					uint32_t sextet_a = get_sextet(i++);
					uint32_t sextet_b = get_sextet(i++);
					uint32_t sextet_c = get_sextet(i++);
					uint32_t sextet_d = get_sextet(i++);

					uint32_t triple =
						(sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

					res += static_cast<char>((triple >> 2 * 8) & 0xFFU);
					res += static_cast<char>((triple >> 1 * 8) & 0xFFU);
					res += static_cast<char>((triple >> 0 * 8) & 0xFFU);
				}

				if (pad.count == 0) return res;

				uint32_t triple = (get_sextet(fast_size) << 3 * 6) + (get_sextet(fast_size + 1) << 2 * 6);

				switch (pad.count) {
				case 1:
					triple |= (get_sextet(fast_size + 2) << 1 * 6);
					res += static_cast<char>((triple >> 2 * 8) & 0xFFU);
					res += static_cast<char>((triple >> 1 * 8) & 0xFFU);
					break;
				case 2: res += static_cast<char>((triple >> 2 * 8) & 0xFFU); break;
				default: break;
				}

				return res;
			}

			inline std::string pad(string_view base, string_view fill) {
				std::string res(base);
				switch (res.size() % 4) {
				case 1: res += fill; JWT_FALLTHROUGH;
				case 2: res += fill; JWT_FALLTHROUGH;
				case 3: res += fill; JWT_FALLTHROUGH;
				default: break;
				}
				return res;
			}

			inline std::string trim(string_view base, string_view fill) {
				auto pos = base.find(fill);
				return static_cast<std::string>(base.substr(0, pos));
			}
		} // namespace details

#ifdef JWT_HAS_STRING_VIEW
		template<typename T>
		std::string encode(string_view bin) {
			return details::encode(bin, T::kData, T::kFill[0]);
		}
		template<typename T>
		std::string decode(string_view base) {
			return details::decode(base, std::begin(T::kData), std::end(T::kData), std::begin(T::kFill),
								   std::end(T::kFill));
		}
		template<typename T>
		std::string pad(string_view base) {
			return details::pad(base, T::kFill[0]);
		}
		template<typename T>
		std::string trim(string_view base) {
			return details::trim(base, T::kFill[0]);
		}

#else
		template<typename T>
		std::string encode(string_view bin) {
			return details::encode(bin, T::data().data(), T::fill()[0]);
		}
		template<typename T>
		std::string decode(string_view base) {
			return details::decode(base, std::begin(T::data()), std::end(T::data()), std::begin(T::fill()),
								   std::end(T::fill()));
		}
		template<typename T>
		std::string pad(string_view base) {
			return details::pad(base, T::fill()[0]);
		}
		template<typename T>
		std::string trim(string_view base) {
			return details::trim(base, T::fill()[0]);
		}
#endif
	} // namespace base
} // namespace jwt

#undef JWT_BASE_ALPHABET

#endif
