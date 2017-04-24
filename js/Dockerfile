FROM debian:sid

RUN apt-get update \
 && apt-get install -y --force-yes --no-install-recommends \
      build-essential \
      libtool \
      autotools-dev \
      automake \
      libmicrohttpd-dev \
      libcurl4-gnutls-dev \
      nettle-dev \
      libjson-c-dev \
      libuv1-dev \
      bsdmainutils \
 && rm -rf /var/lib/apt/lists/*;

RUN apt-get update \
 && apt-get install -y --force-yes --no-install-recommends \
      curl \
      ca-certificates \
      python-all \
 && rm -rf /var/lib/apt/lists/*;

RUN apt-get update \
 && apt-get install -y --force-yes --no-install-recommends \
      cmake \
 && rm -rf /var/lib/apt/lists/*;


WORKDIR /usr/src/emscripten
RUN curl https://s3.amazonaws.com/mozilla-games/emscripten/releases/emsdk-portable.tar.gz \
  | tar -xzv --strip-components 1

RUN ./emsdk update
RUN ./emsdk install latest
RUN ./emsdk activate latest

RUN apt-get update \
 && apt-get install -y --force-yes --no-install-recommends \
      gnupg \
 && curl -sL https://deb.nodesource.com/setup_6.x \
  | bash - \
 && apt-get install -y --force-yes --no-install-recommends \
      nodejs \
      openjdk-8-jre \
      openjdk-8-jdk \
 && rm -rf /var/lib/apt/lists/*;

RUN bash -c 'source ./emsdk_env.sh && emcc -v && emcc emscripten/tag-*/tests/hello_123.c -o h.js && rm h.js'

WORKDIR /usr/src/libstorj
ADD ./ ./

RUN ./js/compile.sh

CMD ["cat", "src/rs.js"]
