# Build the main Kubidmd server
ARG BASE_IMAGE=debian:trixie-slim

FROM rust:1 AS builder
ARG KUBIDM_FEATURES
ARG KUBIDM_BUILD_PROFILE="container_generic"
ARG KUBIDM_BUILD_OPTIONS=""

ENV KUBIDM_BUILD_PROFILE=${KUBIDM_BUILD_PROFILE:-container_generic}
ENV RUSTFLAGS="-Clinker=clang"
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN apt-get update && apt-get install -y --no-install-recommends \
    sccache \
    clang \
    cmake \
    gcc \
    make \
    automake \
    autoconf \
    libpam0g-dev \
    libsqlite3-dev \
    libcap-dev \
    libsystemd-dev \
    rsync \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-auditable

COPY . /usr/src/kubidm

WORKDIR /usr/src/kubidm/server/daemon

RUN --mount=type=cache,id=cargo,target=/cargo \
    --mount=type=cache,id=sccache,target=/sccache \
    export CARGO_HOME=/cargo && \
    export SCCACHE_DIR=/sccache && \
    export RUSTC_WRAPPER=/usr/bin/sccache && \
    export CC="/usr/bin/clang" && \
    cargo fetch --locked && \
    export CARGO_NET_OFFLINE=true && \
    cargo auditable build --locked -p daemon ${KUBIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/kubidm/target/" \
        --features="${KUBIDM_FEATURES}" \
        --release; \
    ls -alh /usr/src/kubidm/target/release; \
    sccache -s

RUN <<EOF
    mkdir -p /out/libs
    mkdir -p /out/libs-root
    ldd /usr/src/kubidm/target/release/kubidmd
    ldd /usr/src/kubidm/target/release/kubidmd | grep -v 'linux-vdso.so' | awk '{print $(NF-1) " " $1}' | sort -u -k 1,1 | awk '{print "install", "-D", $1, (($2 ~ /^\//) ? "/out/libs-root" $2 : "/out/libs/" $2)}' | xargs -I {} sh -c {}
    ls -Rla /out/libs
    ls -Rla /out/libs-root
EOF

FROM scratch

WORKDIR /

COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder --chmod=0755 /usr/src/kubidm/target/release/kubidmd /sbin/
COPY --from=builder /usr/src/kubidm/server/core/static /hpkg/

COPY --from=builder /out/libs-root/ /
COPY --from=builder /out/libs/ /lib/

ENV LD_LIBRARY_PATH=/lib

WORKDIR /data

EXPOSE 8443 3636

ENV RUST_BACKTRACE=1

HEALTHCHECK \
    --interval=60s \
    --timeout=10s \
    --start-period=60s \
    --start-interval=5s \
    --retries=3 \
    CMD [ "/sbin/kubidmd", "scripting", "healthcheck"]

CMD [ "/sbin/kubidmd", "server"]
