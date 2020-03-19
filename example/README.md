# Print Claims Example

Simple demo showing the usage along with vcpkg.

```sh
cmake -DVCPKG_TARGET_TRIPLET=x64-linux -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/vcpkg/scripts/buildsystems/vcpkg.cmake .
make
```
