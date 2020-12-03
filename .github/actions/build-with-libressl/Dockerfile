FROM ubuntu:latest

RUN apt-get -y update && apt-get install -y g++ cmake wget

RUN wget https://raw.githubusercontent.com/libressl-portable/portable/v3.3.0/FindLibreSSL.cmake -P /cmake && \
      cd /tmp && \
      wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.3.0.tar.gz && \
      tar -zvxf /tmp/libressl-3.3.0.tar.gz  && \
      cd libressl-3.3.0 && \
      ./configure && \
      make -j $(nproc) install
