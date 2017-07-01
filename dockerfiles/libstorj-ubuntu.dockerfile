FROM ubuntu:latest
MAINTAINER Storj Labs (bill@storj.io)

ADD https://raw.githubusercontent.com/computeronix/libstorj/master/dockerfiles/get_dep_ver.sh get_dep_ver.sh

RUN apt-get update && \
    apt-get -y install wget && \
    chmod +x get_dep_ver.sh && \
    ./get_dep_ver.sh && \
    LIBSTORJ_VERSION=$(cat libstorj) && \
    wget https://github.com/Storj/libstorj/releases/download/v$LIBSTORJ_VERSION/libstorj-$LIBSTORJ_VERSION-linux64.tar.gz -O libstorj.tar.gz && \
    tar -zxvf libstorj.tar.gz && \
    mv libstorj-$LIBSTORJ_VERSION/bin/storj /bin && \
    rm -rf libstorj* && \
    apt-get --purge remove -y wget && \
    apt autoremove -y && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/npm* && \
    rm -rf get_dep_ver.sh && \
    rm -rf libstorj && \
    echo storj --version; storj --version && \
    echo storj get-info; storj get-info
