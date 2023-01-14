#include "jwt-cpp/base.h"
#include <gtest/gtest.h>

namespace jwt {

	namespace base {
		namespace details {
			inline bool operator==(const padding& lhs, const padding& rhs) {
				return lhs.count == rhs.count && lhs.length == rhs.length;
			}
		} // namespace details
	}	  // namespace base

	namespace {
		base::details::padding count_padding(string_view base, std::initializer_list<std::string> fills) {
			return base::details::count_padding(base, fills.begin(), fills.end());
		}
	} // namespace

	TEST(BaseTest, Base64Index) {
#ifdef JWT_HAS_STRING_VIEW
		ASSERT_EQ(0, alphabet::index(std::begin(alphabet::base64::kData), std::end(alphabet::base64::kData), 'A'));
		ASSERT_EQ(32, alphabet::index(std::begin(alphabet::base64::kData), std::end(alphabet::base64::kData), 'g'));
		ASSERT_EQ(62, alphabet::index(std::begin(alphabet::base64::kData), std::end(alphabet::base64::kData), '+'));
#else
		ASSERT_EQ(0, alphabet::index(std::begin(alphabet::base64::data()), std::end(alphabet::base64::data()), 'A'));
		ASSERT_EQ(32, alphabet::index(std::begin(alphabet::base64::data()), std::end(alphabet::base64::data()), 'g'));
		ASSERT_EQ(62, alphabet::index(std::begin(alphabet::base64::data()), std::end(alphabet::base64::data()), '+'));
#endif
	}

	TEST(BaseTest, Base64URLIndex) {
#ifdef JWT_HAS_STRING_VIEW
		ASSERT_EQ(0,
				  alphabet::index(std::begin(alphabet::base64url::kData), std::end(alphabet::base64url::kData), 'A'));
		ASSERT_EQ(32,
				  alphabet::index(std::begin(alphabet::base64url::kData), std::end(alphabet::base64url::kData), 'g'));
		ASSERT_EQ(62,
				  alphabet::index(std::begin(alphabet::base64url::kData), std::end(alphabet::base64url::kData), '-'));
#else
		ASSERT_EQ(0,
				  alphabet::index(std::begin(alphabet::base64url::data()), std::end(alphabet::base64url::data()), 'A'));
		ASSERT_EQ(32,
				  alphabet::index(std::begin(alphabet::base64url::data()), std::end(alphabet::base64url::data()), 'g'));
		ASSERT_EQ(62,
				  alphabet::index(std::begin(alphabet::base64url::data()), std::end(alphabet::base64url::data()), '-'));
#endif
	}

	TEST(BaseTest, BaseDetailsCountPadding) {
		using base::details::padding;
		ASSERT_EQ(padding{}, count_padding("ABC", {"~"}));
		ASSERT_EQ((padding{3, 3}), count_padding("ABC~~~", {"~"}));
		ASSERT_EQ((padding{5, 5}), count_padding("ABC~~~~~", {"~"}));

		ASSERT_EQ(padding{}, count_padding("ABC", {"~", "!"}));
		ASSERT_EQ((padding{1, 1}), count_padding("ABC!", {"~", "!"}));
		ASSERT_EQ((padding{1, 1}), count_padding("ABC~", {"~", "!"}));
		ASSERT_EQ((padding{3, 3}), count_padding("ABC~~!", {"~", "!"}));
		ASSERT_EQ((padding{3, 3}), count_padding("ABC!~~", {"~", "!"}));
		ASSERT_EQ((padding{5, 5}), count_padding("ABC~~!~~", {"~", "!"}));

		ASSERT_EQ((padding{2, 6}), count_padding("MTIzNA%3d%3d", {"%3d", "%3D"}));
		ASSERT_EQ((padding{2, 6}), count_padding("MTIzNA%3d%3D", {"%3d", "%3D"}));
		ASSERT_EQ((padding{2, 6}), count_padding("MTIzNA%3D%3d", {"%3d", "%3D"}));
		ASSERT_EQ((padding{2, 6}), count_padding("MTIzNA%3D%3D", {"%3d", "%3D"}));

		// Some fake scenarios

		ASSERT_EQ(padding{}, count_padding("", {"~"}));
		ASSERT_EQ(padding{}, count_padding("ABC", {"~", "~~!"}));
		ASSERT_EQ(padding{}, count_padding("ABC!", {"~", "~~!"}));
		ASSERT_EQ((padding{1, 1}), count_padding("ABC~", {"~", "~~!"}));
		ASSERT_EQ((padding{1, 3}), count_padding("ABC~~!", {"~", "~~!"}));
		ASSERT_EQ((padding{2, 2}), count_padding("ABC!~~", {"~", "~~!"}));
		ASSERT_EQ((padding{3, 5}), count_padding("ABC~~!~~", {"~", "~~!"}));
		ASSERT_EQ(padding{}, count_padding("ABC~~!~~", {}));
	}

	TEST(BaseTest, Base64Decode) {
		ASSERT_EQ("1", base::decode<alphabet::base64>("MQ=="));
		ASSERT_EQ("12", base::decode<alphabet::base64>("MTI="));
		ASSERT_EQ("123", base::decode<alphabet::base64>("MTIz"));
		ASSERT_EQ("1234", base::decode<alphabet::base64>("MTIzNA=="));
	}

	TEST(BaseTest, Base64DecodeURL) {
		ASSERT_EQ("1", base::decode<alphabet::base64url>("MQ%3d%3d"));
		ASSERT_EQ("12", base::decode<alphabet::base64url>("MTI%3d"));
		ASSERT_EQ("123", base::decode<alphabet::base64url>("MTIz"));
		ASSERT_EQ("1234", base::decode<alphabet::base64url>("MTIzNA%3d%3d"));
	}

	TEST(BaseTest, Base64DecodeURLCaseInsensitive) {
		ASSERT_EQ("1", base::decode<alphabet::helper::base64url_percent_encoding>("MQ%3d%3d"));
		ASSERT_EQ("1", base::decode<alphabet::helper::base64url_percent_encoding>("MQ%3D%3d"));
		ASSERT_EQ("1", base::decode<alphabet::helper::base64url_percent_encoding>("MQ%3d%3D"));
		ASSERT_EQ("12", base::decode<alphabet::helper::base64url_percent_encoding>("MTI%3d"));
		ASSERT_EQ("123", base::decode<alphabet::helper::base64url_percent_encoding>("MTIz"));
		ASSERT_EQ("1234", base::decode<alphabet::helper::base64url_percent_encoding>("MTIzNA%3d%3d"));
		ASSERT_EQ("1234", base::decode<alphabet::helper::base64url_percent_encoding>("MTIzNA%3D%3D"));
	}

	TEST(BaseTest, Base64Encode) {
		ASSERT_EQ("MQ==", base::encode<alphabet::base64>("1"));
		ASSERT_EQ("MTI=", base::encode<alphabet::base64>("12"));
		ASSERT_EQ("MTIz", base::encode<alphabet::base64>("123"));
		ASSERT_EQ("MTIzNA==", base::encode<alphabet::base64>("1234"));
	}

	TEST(BaseTest, Base64EncodeURL) {
		ASSERT_EQ("MQ%3d%3d", base::encode<alphabet::base64url>("1"));
		ASSERT_EQ("MTI%3d", base::encode<alphabet::base64url>("12"));
		ASSERT_EQ("MTIz", base::encode<alphabet::base64url>("123"));
		ASSERT_EQ("MTIzNA%3d%3d", base::encode<alphabet::base64url>("1234"));
	}

	TEST(BaseTest, Base64Pad) {
		ASSERT_EQ("MQ==", base::pad<alphabet::base64>("MQ"));
		ASSERT_EQ("MTI=", base::pad<alphabet::base64>("MTI"));
		ASSERT_EQ("MTIz", base::pad<alphabet::base64>("MTIz"));
		ASSERT_EQ("MTIzNA==", base::pad<alphabet::base64>("MTIzNA"));
	}

	TEST(BaseTest, Base64PadURL) {
		ASSERT_EQ("MQ%3d%3d", base::pad<alphabet::base64url>("MQ"));
		ASSERT_EQ("MTI%3d", base::pad<alphabet::base64url>("MTI"));
		ASSERT_EQ("MTIz", base::pad<alphabet::base64url>("MTIz"));
		ASSERT_EQ("MTIzNA%3d%3d", base::pad<alphabet::base64url>("MTIzNA"));
	}

	TEST(BaseTest, Base64Trim) {
		ASSERT_EQ("MQ", base::trim<alphabet::base64>("MQ=="));
		ASSERT_EQ("MTI", base::trim<alphabet::base64>("MTI="));
		ASSERT_EQ("MTIz", base::trim<alphabet::base64>("MTIz"));
		ASSERT_EQ("MTIzNA", base::trim<alphabet::base64>("MTIzNA=="));
	}

	TEST(BaseTest, Base64TrimURL) {
		ASSERT_EQ("MQ", base::trim<alphabet::base64url>("MQ%3d%3d"));
		ASSERT_EQ("MTI", base::trim<alphabet::base64url>("MTI%3d"));
		ASSERT_EQ("MTIz", base::trim<alphabet::base64url>("MTIz"));
		ASSERT_EQ("MTIzNA", base::trim<alphabet::base64url>("MTIzNA%3d%3d"));
	}
} // namespace jwt