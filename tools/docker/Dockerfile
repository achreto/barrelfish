# Copyright (c) 2021, 2022 The University of British Columbia.
# All rights reserved.
#
# This file is distributed under the terms in the attached LICENSE file.

FROM ubuntu:22.04
MAINTAINER Reto Achermann <achreto@cs.ubc.ca>

# update the repositories
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get upgrade -y

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
# some system dependencies
    python3 parted wget mtools \
# barrelfish dependencies
    build-essential pkg-config bison flex ghc libghc-src-exts-dev \
    libghc-ghc-paths-dev libghc-parsec3-dev libghc-random-dev\
    libghc-ghc-mtl-dev libghc-async-dev picocom cabal-install \
    git gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
    qemu-efi-aarch64 qemu-system-arm qemu-utils libelf-dev \
    gdb-multiarch \
# install the autograder dependencies
    python3 python3-pexpect  python3-plumbum

# install the remaining haskell package
RUN cabal v1-update && \
    cabal v1-install --global bytestring-trie

# get the uuu tool
RUN wget -P /bin https://github.com/NXPmicro/mfgtools/releases/download/uuu_1.4.165/uuu && \
    chmod 755 /bin/uuu

# create the tools directory
RUN mkdir /source && \
    chmod 755 /source

# clean the apt
RUN apt-get clean && apt-get autoclean && apt-get autoremove -y


COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
