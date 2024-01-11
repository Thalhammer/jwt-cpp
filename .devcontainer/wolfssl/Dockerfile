FROM ubuntu:22.04

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update && apt-get -y install \
    autoconf \
    build-essential \
    clang-format \
    clang-tidy \
    cmake \
    doxygen \
    graphviz \
    git \
    g++ \
    libgtest-dev \
    libtool \
    wget \
    && rm -rf /var/lib/apt/lists/*

# https://www.warp.dev/terminus/dockerfile-run-sh
COPY ./.github/actions/install/wolfssl/install.sh /wolfssl/install.sh
RUN /wolfssl/install.sh

ENV JWT_SSL_LIBRARY="wolfSSL"
ENV CMAKE_C_CLANG_TIDY="clang-tidy;-fix"
ENV CMAKE_CXX_CLANG_TIDY="clang-tidy;-fix"
