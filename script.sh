BF_SOURCE=$(readlink -f `pwd`)
BF_BUILD=$BF_SOURCE/build
BF_DOCKER=achreto/barrelfish-ci:20.04-lts

ARM_FASTMODELS_PATH=$HOME/bin/arm/

if [ -d ${ARM_FASTMODELS_PATH} ];
then
  echo "mounting fastmodels"
  FAST_MODELS_MOUNT="--mount type=bind,source=$ARM_FASTMODELS_PATH,target=$ARM_FASTMODELS_PATH"
else
  FAST_MODELS_MOUNT=
fi

echo "bfdocker: $BF_DOCKER"
echo "bfsrc: $BF_SOURCE  build: $BF_BUILD"

# pull the docker image
docker pull $BF_DOCKER

# create the build directory
mkdir -p $BF_BUILD




# run the command in the docker image
docker run -u $(id -u) -i -t \
    --mount type=bind,source=$BF_SOURCE,target=/source \
    --mount type=bind,source=$BF_BUILD,target=/source/build \
    $FAST_MODELS_MOUNT \
    $BF_DOCKER
