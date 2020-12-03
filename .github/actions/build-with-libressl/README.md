# LibreSSL build context

This provides an easy way to test LibreSSL configurations without disturbing your system's regular OpenSSL enviroment.

```sh
docker build -t ${your_image_name} $(pwd)
docker run -it -v "$(pwd):/home/jwt-cpp" ${your_image_name}
```
