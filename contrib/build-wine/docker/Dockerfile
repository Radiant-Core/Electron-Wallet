### https://raw.githubusercontent.com/Electron-Cash/Electron-Cash/master/contrib/build-wine/docker/Dockerfile

FROM ubuntu:22.04@sha256:42ba2dfce475de1113d55602d40af18415897167d47c2045ec7b6d9746ff148f

ARG UBUNTU_MIRROR=http://archive.ubuntu.com/ubuntu/

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

ENV UBUNTUDIST=jammy

# This prevents questions during package installations
ENV DEBIAN_FRONTEND=noninteractive

RUN echo deb ${UBUNTU_MIRROR} ${UBUNTUDIST} main restricted universe multiverse > /etc/apt/sources.list && \
    echo deb ${UBUNTU_MIRROR} ${UBUNTUDIST}-updates main restricted universe multiverse >> /etc/apt/sources.list && \
    echo deb ${UBUNTU_MIRROR} ${UBUNTUDIST}-backports main restricted universe multiverse >> /etc/apt/sources.list && \
    echo deb ${UBUNTU_MIRROR} ${UBUNTUDIST}-security main restricted universe multiverse >> /etc/apt/sources.list && \
    dpkg --add-architecture i386 && \
    apt-get update -q && \
    apt-get install -qy \
        gnupg2 \
        ca-certificates \
        wget \
        git \
        p7zip-full \
        make \
        autotools-dev \
        autoconf \
        libtool \
        gettext \
        autopoint \
        mingw-w64 \
        mingw-w64-tools \
        win-iconv-mingw-w64-dev

# Official WineHQ signing key
# See https://wiki.winehq.org/Ubuntu
# From https://dl.winehq.org/wine-builds/winehq.key
COPY winehq.key /tmp

ENV WINEDIST=devel
ENV WINEVERSION=7.7~${UBUNTUDIST}-1
###################################################

# Modified wine installation code to prevent compiling problems

RUN mkdir -pm755 /etc/apt/keyrings && \
    wget https://dl.winehq.org/wine-builds/winehq.key -O "/etc/apt/keyrings/winehq-archive.key" && \
    wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/jammy/winehq-jammy.sources && \
    apt-get update  && apt-get install -y winehq-devel winbind xvfb cabextract

####################################################
RUN rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

RUN wget -q -O /tmp/winetricks https://raw.githubusercontent.com/Winetricks/winetricks/9c97d44b9b68a1b09e244e46f9ae0831ab35c315/src/winetricks && \
    chmod +x /tmp/winetricks && \
    echo "311c8c223bb83a7558b9e51197a9ccf7182bbd63849c64827b87bbc5f627f5cb /tmp/winetricks" | sha256sum -c -

ARG USER_ID
ARG GROUP_ID

ENV HOME=/homedir
ENV WINEARCH=win32
ENV WINEPREFIX=${HOME}/wine
ENV WINEDEBUG=-all

RUN mkdir -p ${WINEPREFIX}/drive_c/electronradiant ; chown -R ${USER_ID}:${GROUP_ID} ${HOME}

# Make our UID/GID have an actual user name, this is needed so wineboot creates the right folders and
# the Visual Studio installer does't fail in SHGetKnownFolderPath with error 0x80070003 (ERROR_PATH_NOT_FOUND).
RUN echo "user:x:${USER_ID}:${GROUP_ID}::${HOME}:/bin/sh" >> /etc/passwd
USER ${USER_ID}:${GROUP_ID}

WORKDIR ${HOME}

# wineboot needs to run after the user is added to /etc/passwd, otherwise it will assume the username is "wine"
RUN wineboot && \
    # Wait for the wine server to shutdown, needs to be done after wineboot to ensure the installation is good
    wineserver -w

# DBUS_FATAL_WARNINGS=0 is needed because we don't have dbus in the container and Wine calls
# dbus_connection_send_with_reply_and_block with a NULL connection. The dbus client libraries are set to abort by
# default unless this variable is set.
ENV DBUS_FATAL_WARNINGS=0

# VS Build Tools / dotnet472 were removed: their only consumer was pyscard's
# MSVC-compiled sdist, which is now filtered out of requirements-hw.txt.
# All native builds in this image go through mingw-w64 instead.

# Clean up packages only needed for the removed .NET / Visual Studio installer
USER 0:0
RUN apt-get remove cabextract xvfb -y && \
    apt-get autoremove -y
USER ${USER_ID}:${GROUP_ID}
