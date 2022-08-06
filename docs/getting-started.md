# Getting started

## Installation

There's a number of options to choice from.

It's strongly recommended to use a package manager. Currently Conan, Hunter, and Vcpkg are support.
If the version is out of date please check with their respective communities before opening and issue here.

When manually adding this dependecy, check the examples or automated tests.

## Header Only

Simply downloading the `include/` directory is possible.
Make sure the `jwt-cpp/` is visible.
This does require correctly linking to OpenSSL or alternative.

:information_source: The minimum is `jwt.h` but you will need to disable Base64 and the default Picojso trait.

## CMake

Using `find_package` is recommended. Step you environment but configuring and installing the `jwt-cpp::jwt-cpp` target.
This will automatically select the the same SSL library when detected with `find_package`.

A simple installation may look like

```sh
cmake .
cmake --install .
```

Using `add_subdirectory` is untested but should work.

## Extrnal JSON dependencies 

The `include/` currently include both PicoJSIN and NLohmann JSON.
When importing these from other sources you may see known bugs (add link)

## Conan

See example (needs update)

## Hunter

Add example?

## Vcpk

Add example?

