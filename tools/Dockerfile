# This builds the Kubidm CLI tools
ARG BASE_IMAGE=debian:trixie-slim

FROM rust:1 AS builder
ARG KUBIDM_FEATURES
ARG KUBIDM_BUILD_PROFILE
ARG KUBIDM_BUILD_OPTIONS=""

ENV KUBIDM_BUILD_PROFILE=${KUBIDM_BUILD_PROFILE:-container_generic}
ENV RUSTFLAGS="-Clinker=clang"
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN apt-get update && apt-get install -y --no-install-recommends \
    sccache \
    clang \
    gcc \
    make \
    automake \
    autoconf \
    libpam0g-dev \
    libudev-dev \
    libsqlite3-dev \
    rsync \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-auditable

COPY . /usr/src/kubidm

WORKDIR /usr/src/kubidm/

RUN \
    --mount=type=cache,id=cargo,target=/cargo \
    --mount=type=cache,id=sccache,target=/sccache \
    export CARGO_HOME=/cargo; \
    export SCCACHE_DIR=/sccache; \
    export RUSTC_WRAPPER=/usr/bin/sccache; \
    export CC="/usr/bin/clang"; \
    cargo fetch --locked && \
    export CARGO_NET_OFFLINE=true; \
    cargo auditable build --locked -p kubidm_tools ${KUBIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/kubidm/target/" \
        --features="${KUBIDM_FEATURES}" \
        --release && \
    cargo auditable build --locked -p kubidm-ipa-sync ${KUBIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/kubidm/target/" \
        --features="${KUBIDM_FEATURES}" \
        --release && \
    cargo auditable build --locked -p kubidm-ldap-sync ${KUBIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/kubidm/target/" \
        --features="${KUBIDM_FEATURES}" \
        --release && \
    cargo auditable build --locked -p kubidm-mail-sender ${KUBIDM_BUILD_OPTIONS} \
        --target-dir="/usr/src/kubidm/target/" \
        --features="${KUBIDM_FEATURES}" \
        --release && \
    unset CARGO_NET_OFFLINE && \
    cargo auditable install \
        --git https://github.com/kanidm/webauthn-rs.git \
        --rev 2ac5ff0e20f323cd904856a38a15899adf13fa5b \
        --force fido-mds-tool \
        --target-dir="/usr/src/kubidm/target/" && \
    sccache -s

FROM ${BASE_IMAGE}

ENV RUST_BACKTRACE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssl \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder --chmod=0755 /usr/src/kubidm/target/release/kubidm /sbin/
COPY --from=builder --chmod=0755 /usr/src/kubidm/target/release/kubidm-ipa-sync /sbin/
COPY --from=builder --chmod=0755 /usr/src/kubidm/target/release/kubidm-ldap-sync /sbin/
COPY --from=builder --chmod=0755 /usr/src/kubidm/target/release/kubidm-mail-sender /sbin/
COPY --from=builder --chmod=0755 /usr/src/kubidm/target/release/fido-mds-tool /sbin/

RUN mkdir /etc/kubidm && \
    touch /etc/kubidm/config

CMD [ "/sbin/kubidm", "-h" ]
