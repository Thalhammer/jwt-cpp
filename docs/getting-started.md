# Getting started

## Installation

There's a number of options to choice from.

It's strongly recommended to use a package manager. Currently Conan, Hunter, and Vcpkg are support.
If the version is out of date please check with their respective communities before opening and issue here.

When manually adding this dependecy, check the examples or automated tests.

### Header Only

Simply downloading the `include/` directory is possible.
Make sure the `jwt-cpp/` is visible.
This does require correctly linking to OpenSSL or alternative.

:information_source: The minimum is `jwt.h` but you will need to add the deinfes [`JWT_DISABLE_BASE64`](https://github.com/Thalhammer/jwt-cpp/blob/c9a511f436eaa13857336ebeb44dbc5b7860fe01/include/jwt-cpp/jwt.h#L11) and [`JWT_DISABLE_PICOJSON`](https://github.com/Thalhammer/jwt-cpp/blob/c9a511f436eaa13857336ebeb44dbc5b7860fe01/include/jwt-cpp/jwt.h#L4).

### CMake

Using `find_package` is recommended. Step you environment but configuring and installing the `jwt-cpp::jwt-cpp` target.
This will automatically select the the same SSL library when detected with `find_package`.

A simple installation may look like

```sh
cmake .
cmake --install .
```

Using `add_subdirectory` is untested but should work.

## External JSON dependencies 

The `include/` currently include both PicoJSON and NLohmann JSON.
When importing these from other sources you may see known bugs (add link)

### Conan

See example (needs update)

### Hunter

Add example?

### Vcpk

Add example?

