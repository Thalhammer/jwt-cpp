FROM ubuntu:22.04

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update && apt-get -y install \
    clang++ \
    clang-format \
    clang-tidy \
    cmake \
    doxygen \
    graphviz \
    git \
    g++ \
    libssl-dev \
    libgtest-dev \
    && rm -rf /var/lib/apt/lists/*

ENV CMAKE_CXX_CLANG_TIDY="clang-tidy;-fix"
