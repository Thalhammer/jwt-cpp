# Getting Started

There's a number of options to choice from.

## Installation

It's strongly recommended to use a package manager, as JWT-CPP has dependencies for both 
cryptography and JSON libraries, having a tool to do the heavily lifting can be ideal.
Examples of a C and C++ package manager are [Conan](https://conan.io/) and [vcpkg](https://vcpkg.io/). If the version is out of date please check with their respective communities before opening and issue here.

When manually adding this dependency, and the dependencies this has, check the GitHub Actions and Workflows for some inspiration about how to go about it.

### Package Manager

- Conan: https://conan.io/center/recipes/jwt-cpp
- vcpkg: https://vcpkg.link/ports/jwt-cpp
- Nuget: https://www.nuget.org/packages/jwt-cpp/
- Hunter: https://hunter.readthedocs.io/en/latest/packages/pkg/jwt-cpp.html
- Spack: https://packages.spack.io/package.html?name=jwt-cpp
- Xrepo: https://xrepo.xmake.io/#/packages/linux?id=jwt-cpp-linux

Looking for ways to contribute? Help by adding JWT-CPP to your favorite package manager!
[Nixpkgs](https://github.com/NixOS/nixpkgs) for example. Currently many are behind the latest.

### Header Only

Simply downloading the `include/` directory is possible.
Make sure the `jwt-cpp/` subdirectories is visible during compilation.
This **does require** correctly linking to OpenSSL or alternative cryptography library.

The minimum is `jwt.h` but you will need to add the defines:

- [`JWT_DISABLE_BASE64`](https://github.com/Thalhammer/jwt-cpp/blob/c9a511f436eaa13857336ebeb44dbc5b7860fe01/include/jwt-cpp/jwt.h#L11)
- [`JWT_DISABLE_PICOJSON`](https://github.com/Thalhammer/jwt-cpp/blob/c9a511f436eaa13857336ebeb44dbc5b7860fe01/include/jwt-cpp/jwt.h#L4)

In addition to providing your own JSON traits implementation, see [traits.md](traits.ms) for more information.

### CMake

Using `find_package` is recommended. Step you environment but configuring and installing the `jwt-cpp` target. This will automatically select the the same SSL library when detected with `find_package`.

A simple installation may look like

```sh
cmake . -DJWT_BUILD_EXAMPLES=OFF
cmake --install .
```

```cmake
find_package(jwt-cpp CONFIG REQUIRED)

target_link_libraries(my_app PRIVATE jwt-cpp::jwt-cpp)
```

There's also the possibility of using [`FetchContent`](https://cmake.org/cmake/help/latest/module/FetchContent.html#examples) in pull this this project to your build tree.

```cmake
include(FetchContent)
fetchcontent_declare(jwt-cpp GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git GIT_TAG v0.7.0)
fetchcontent_makeavailable(jwt-cpp)

target_link_libraries(my_app PRIVATE jwt-cpp::jwt-cpp)
```

Lastly, you can use `add_subdirectory`, this is untested but should work.
