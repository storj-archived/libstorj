FROM alpine:latest
MAINTAINER Storj Labs (bill@storj.io)

ENV LANG=C.UTF-8

ADD https://raw.githubusercontent.com/computeronix/libstorj/master/dockerfiles/get_dep_ver.sh get_dep_ver.sh

RUN ALPINE_GLIBC_BASE_URL="https://github.com/sgerrand/alpine-pkg-glibc/releases/download" && \
    ALPINE_GLIBC_PACKAGE_VERSION="2.25-r0" && \
    ALPINE_GLIBC_BASE_PACKAGE_FILENAME="glibc-$ALPINE_GLIBC_PACKAGE_VERSION.apk" && \
    ALPINE_GLIBC_BIN_PACKAGE_FILENAME="glibc-bin-$ALPINE_GLIBC_PACKAGE_VERSION.apk" && \
    ALPINE_GLIBC_I18N_PACKAGE_FILENAME="glibc-i18n-$ALPINE_GLIBC_PACKAGE_VERSION.apk" && \
    apk update && apk add --no-cache --virtual=.build-dependencies && \
    apk add --no-cache wget ca-certificates bash && \
    wget \
        "https://raw.githubusercontent.com/andyshinn/alpine-pkg-glibc/master/sgerrand.rsa.pub" \
        -O "/etc/apk/keys/sgerrand.rsa.pub" && \
    wget \
        "$ALPINE_GLIBC_BASE_URL/$ALPINE_GLIBC_PACKAGE_VERSION/$ALPINE_GLIBC_BASE_PACKAGE_FILENAME" \
        "$ALPINE_GLIBC_BASE_URL/$ALPINE_GLIBC_PACKAGE_VERSION/$ALPINE_GLIBC_BIN_PACKAGE_FILENAME" \
        "$ALPINE_GLIBC_BASE_URL/$ALPINE_GLIBC_PACKAGE_VERSION/$ALPINE_GLIBC_I18N_PACKAGE_FILENAME" && \
    apk add --no-cache \
        "$ALPINE_GLIBC_BASE_PACKAGE_FILENAME" \
        "$ALPINE_GLIBC_BIN_PACKAGE_FILENAME" \
        "$ALPINE_GLIBC_I18N_PACKAGE_FILENAME" && \
    \
    rm "/etc/apk/keys/sgerrand.rsa.pub" && \
    /usr/glibc-compat/bin/localedef --force --inputfile POSIX --charmap UTF-8 C.UTF-8 || true && \
    echo "export LANG=C.UTF-8" > /etc/profile.d/locale.sh && \
    \
    apk del glibc-i18n && \
    \
    chmod +x get_dep_ver.sh && \
    ./get_dep_ver.sh && \
    LIBSTORJ_VERSION=$(cat libstorj) && \
    wget https://github.com/Storj/libstorj/releases/download/v$LIBSTORJ_VERSION/libstorj-$LIBSTORJ_VERSION-linux64.tar.gz -O libstorj.tar.gz && \
    tar -zxvf libstorj.tar.gz && \
    mv libstorj-$LIBSTORJ_VERSION/bin/storj /bin && \
    rm -rf libstorj* && \
    rm -rf /var/cache/apk/* && \
    rm "/root/.wget-hsts" && \
    apk del .build-dependencies wget && \
    rm \
        "$ALPINE_GLIBC_BASE_PACKAGE_FILENAME" \
        "$ALPINE_GLIBC_BIN_PACKAGE_FILENAME" \
        "$ALPINE_GLIBC_I18N_PACKAGE_FILENAME" && \
    rm -rf get_dep_ver.sh && \
    rm -rf libstorj && \
    echo storj --version; storj --version && \
    echo storj get-info; storj get-info
