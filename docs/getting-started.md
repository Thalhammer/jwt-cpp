# Getting started

## Installation

There's a number of options to choice from.

It's strongly recommended to use a package manager. Currently Conan, Hunter, and Vcpkg are support.
If the version is out of date please check with their respective communities before opening and issue here.

When manually adding this dependency, and the dependencies this has, check the examples or automated tests.
For some inspiration about how to go about it.

### Header Only

Simply downloading the `include/` directory is possible.
Make sure the `jwt-cpp/` subdirectories is visible during compilation.
This **does require** correctly linking to OpenSSL or alternative cryptography library.

:information_source: The minimum is `jwt.h` but you will need to add the defines [`JWT_DISABLE_BASE64`](https://github.com/Thalhammer/jwt-cpp/blob/c9a511f436eaa13857336ebeb44dbc5b7860fe01/include/jwt-cpp/jwt.h#L11) and [`JWT_DISABLE_PICOJSON`](https://github.com/Thalhammer/jwt-cpp/blob/c9a511f436eaa13857336ebeb44dbc5b7860fe01/include/jwt-cpp/jwt.h#L4).

### CMake

Using `find_package` is recommended. Step you environment but configuring and installing the `jwt-cpp::jwt-cpp` target.
This will automatically select the the same SSL library when detected with `find_package`.

A simple installation may look like

```sh
cmake .
cmake --install .
```

Using `add_subdirectory` is untested but should work.

There's also the possibility of using `FetchContent` in pull this this project to your build tree.

## External JSON dependencies

### System Package

The `include/` currently include both PicoJSON and if not detected with `find_package` will use `FetchContent` to add `nlohmman_json`.
When importing these from other sources (e.g `apt` on Ubuntu) you may see known bugs (add link)

### Conan

See example (needs update)

### Hunter

Add example?

### Vcpk

Add example?
