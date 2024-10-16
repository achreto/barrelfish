#!/bin/bash

##########################################################################
# Copyright (c) 2019,2020 ETH Zurich.
# Copyright (c) 2021,2022 The University of British Columbia.
# All rights reserved.
#
# This file is distributed under the terms in the attached LICENSE file.
# If you do not find this file, copies can be found by writing to:
# ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
##########################################################################

# set the default docker image to use
BF_DOCKER="achreto/barrelfish-aos:22.04-lts"

# assume the source directory is the current directory
BF_SOURCE=$(git rev-parse --show-toplevel)

# we set the build directory to the source directory to avoid path problems
BF_BUILD=$BF_SOURCE/build

# --privileged enables booting the colibri board from docker
# -t allocate a pseudo-tty
# -i keeps STDIN open and enables us to send keypresses, e.g. to terminate qemu
DOCKER_ARGS="--privileged -t -i"

DOCKER_PULL=true

usage() {
    echo "Usage: $0 <options> [command]"
    echo ""
    echo "Options:"
    echo "   --help: displays this message"
    echo "   --image: container image to use (default: $BF_DOCKER)"
    echo "   --build-dir: build directory for Barrelfish (default: $BF_BUILD)"
    echo "   --no-interactive: do not keep STDIN open"
    echo ""
    echo "When a command is supplied it is executed in the docker container."
    echo "If no command is supplied, an interactive shell in the docker container"
    echo "is started."
    exit 0;
}

while [ $# -ne 0 ]; do
    case $1 in
    "--image")
        BF_DOCKER=$2
        DOCKER_PULL=false
        shift
        ;;
    "--no-interactive")
        DOCKER_ARGS=${DOCKER_ARGS%-i} # remove "-i" from the back of DOCKER_ARGS
        ;;
    "--build-dir")
        BF_BUILD=$2
        shift
        ;;
    "-h"|"--help")
        usage
        ;;
    *)
        break
        ;;
    esac
    shift
done

# pull the docker image if we don't have it yet.
if $DOCKER_PULL ; then
    docker pull $BF_DOCKER
fi

# make sure the build directory exists
mkdir -p $BF_BUILD

# run the command in the docker image with the same userid to avoid
# permission problems later.
docker run -u $(id -u) $DOCKER_ARGS \
    --mount type=bind,source=$BF_SOURCE,target=/source \
    $BF_DOCKER "$@"


