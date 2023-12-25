FROM ubuntu:22.04

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get -y install git g++ cmake libssl-dev libgtest-dev clang-format clang-tidy

ENV CMAKE_CXX_CLANG_TIDY="clang-tidy;-fix"
