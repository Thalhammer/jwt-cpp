#ifndef STRING_TYPES_H
#define STRING_TYPES_H

#if __cplusplus >= 201703L

#include <string_view>

#define JWT_HAS_STRING_VIEW
namespace jwt {
	using string_view = std::string_view;
}

#else

#include <string>
namespace jwt {
	using string_view = const std::string&;
}
#endif

#endif
