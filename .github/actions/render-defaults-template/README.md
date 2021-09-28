# Render `default.h` Templates

## Building

Can be done using `npm run build` but make sure to commit the `dist/` folder.

## Running locally

This expects to be ran from the root directory of the project and can be done using

```sh
INPUT_TRAITS_NAME=my_name INPUT_LIBRARY_NAME="My Awesomename" INPUT_LIBRARY_URL="someurltonowhere" node .github/actions/render-defaults-template/index.js
```

Known configurations are

```sh
INPUT_TRAITS_NAME="danielaparker_jsoncons" INPUT_LIBRARY_NAME="jsoncons" INPUT_LIBRARY_URL="https://github.com/danielaparker/jsoncons" INPUT_DISABLE_DEFAULT_TRAITS=true node .github/actions/render-defaults-template/dist/index.js
INPUT_TRAITS_NAME="boost_json" INPUT_LIBRARY_NAME="Boost.JSON" INPUT_LIBRARY_URL="https://github.com/boostorg/json" INPUT_DISABLE_DEFAULT_TRAITS=true node .github/actions/render-defaults-template/dist/index.jsRendering boost_json!
```
