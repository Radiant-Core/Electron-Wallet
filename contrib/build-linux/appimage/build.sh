#!/bin/bash

here=$(dirname "$0")
test -n "$here" -a -d "$here" || (echo "Cannot determine build dir. FIXME!" && exit 1)

GIT_SUBMODULE_SKIP=1
. "$here"/../../base.sh # functions we use below (fail, et al)
unset GIT_SUBMODULE_SKIP

if [ ! -z "$1" ]; then
    REV="$1"
else
    fail "Please specify a release tag or branch to build (eg: master or 4.0.0, etc)"
fi

if [ ! -d 'contrib' ]; then
    fail "Please run this script form the top-level Electron Radiant git directory"
fi

pushd .


SOURCE_ROOT=`pwd`

overlay_local_fixes() {
    local src_root="$1"
    local dst_root="$2"
    local rel
    for rel in \
        contrib/base.sh \
        contrib/make_locale \
        contrib/make_linux_sdist \
        contrib/make_tor \
        contrib/deterministic-build/requirements-binaries.txt \
        contrib/deterministic-build/requirements-web3.txt \
        contrib/deterministic-build/requirements-hw.txt \
        electroncash_gui/qt/utils/darkdetect/_detect.py \
        contrib/build-linux/appimage/_build.sh \
        contrib/electrum-locale \
        contrib/libevent \
        contrib/openssl \
        contrib/secp256k1 \
        contrib/tor \
        contrib/zbar \
        contrib/zlib
    do
        if [ -e "$src_root/$rel" ]; then
            mkdir -p "$(dirname "$dst_root/$rel")" || fail "Failed to prepare overlay dir for $rel"
            rm -rf "$dst_root/$rel"
            if [ -d "$src_root/$rel" ]; then
                mkdir -p "$dst_root/$rel" || fail "Failed to prepare dir overlay target for $rel"
                if [ -d "$src_root/$rel/.git" ] || [ -f "$src_root/$rel/.git" ]; then
                    (cd "$src_root/$rel" && git archive --format=tar HEAD) | (cd "$dst_root/$rel" && tar -xf -) || fail "Failed to overlay git dir $rel"
                else
                    cp -a "$src_root/$rel/." "$dst_root/$rel/" || fail "Failed to overlay dir $rel"
                fi
            else
                cp -fp "$src_root/$rel" "$dst_root/$rel" || fail "Failed to overlay file $rel"
            fi
        fi
    done
}

docker_version=`docker --version`

if [ "$?" != 0 ]; then
    echo ''
    echo "Please install docker by issuing the following commands (assuming you are on Ubuntu):"
    echo ''
    echo '$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -'
    echo '$ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"'
    echo '$ sudo apt-get update'
    echo '$ sudo apt-get install -y docker-ce'
    echo ''
    fail "Docker is required to build for Windows"
fi

set -e

info "Using docker: $docker_version"

# Only set SUDO if its not been set already
if [ -z ${SUDO+x} ] ; then
    SUDO=""  # on macOS (and others?) we don't do sudo for the docker commands ...
    if [ $(uname) = "Linux" ]; then
        # .. on Linux we do
        SUDO="sudo"
    fi
fi

DOCKER_SUFFIX=ub1804

info "Creating docker image ..."
$SUDO docker build --platform linux/amd64 -t electronradiant-appimage-builder-img-$DOCKER_SUFFIX \
    -f contrib/build-linux/appimage/Dockerfile_$DOCKER_SUFFIX \
    --build-arg UBUNTU_MIRROR=$UBUNTU_MIRROR \
    contrib/build-linux/appimage \
    || fail "Failed to create docker image"

# This is the place where we checkout and put the exact revision we want to work
# on. Docker will run mapping this directory to /opt/electronradiant
# which inside wine will look lik c:\electronradiant
FRESH_CLONE=`pwd`/contrib/build-linux/fresh_clone
FRESH_CLONE_DIR=$FRESH_CLONE/$GIT_DIR_NAME

(
    $SUDO rm -fr $FRESH_CLONE && \
        mkdir -p $FRESH_CLONE && \
        cd $FRESH_CLONE  && \
        git clone "$SOURCE_ROOT" $GIT_DIR_NAME && \
        cd $GIT_DIR_NAME && \
        git checkout $REV
) || fail "Could not create a fresh clone from git"

overlay_local_fixes "$SOURCE_ROOT" "$FRESH_CLONE_DIR"

mkdir "$FRESH_CLONE_DIR/contrib/build-linux/home" || fail "Failed to create home directory"

(
    # NOTE: We propagate forward the GIT_REPO override to the container's env,
    # just in case it needs to see it.
    $SUDO docker run --platform linux/amd64 $DOCKER_RUN_TTY \
    -e HOME="/opt/electronradiant/contrib/build-linux/home" \
    -e GIT_REPO="$GIT_REPO" \
    -e BUILD_DEBUG="$BUILD_DEBUG" \
    --name electronradiant-appimage-builder-cont-$DOCKER_SUFFIX \
    -v $FRESH_CLONE_DIR:/opt/electronradiant:delegated \
    --rm \
    --workdir /opt/electronradiant/contrib/build-linux/appimage \
    -u $(id -u $USER):$(id -g $USER) \
    electronradiant-appimage-builder-img-$DOCKER_SUFFIX \
    ./_build.sh $REV
) || fail "Build inside docker container failed"

popd

info "Copying built files out of working clone..."
mkdir -p dist/
cp -fpvR $FRESH_CLONE_DIR/dist/* dist/ || fail "Could not copy files"

info "Removing $FRESH_CLONE ..."
$SUDO rm -fr $FRESH_CLONE

echo ""
info "Done. Built AppImage has been placed in dist/"
