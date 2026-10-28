ARG BASE_IMAGE=debian:bookworm-slim

FROM ${BASE_IMAGE} AS repos

# ======================
FROM repos AS builder

RUN \
    apt-get update && \
    apt-get install -y \
    libssl-dev \
    clang \
    make \
    sccache \
    cargo \
    pkg-config \
    libtalloc-dev \
    libfreeradius-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /src/kubidm
COPY . /src/kubidm/

WORKDIR /src/kubidm/

# TEMPORARY
RUN cp rlm_kanidm/module/include/automask.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/connection.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/log.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/xlat.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/tmpl.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/clients.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/process.h /usr/include/freeradius/
RUN cp rlm_kanidm/module/include/listen.h /usr/include/freeradius/

RUN --mount=type=cache,id=cargo,target=/cargo \
    --mount=type=cache,id=sccache,target=/sccache \
    export CARGO_HOME=/cargo && \
    export SCCACHE_DIR=/sccache && \
    export RUSTC_WRAPPER=/usr/bin/sccache && \
    export CC="/usr/bin/clang" && \
    cargo build --locked -p rlm_kanidm --features extern-freeradius-module --lib --release && \
    cargo build --locked -p kanidm_radiusd --bin kanidm_radiusd --release && \
    cp /src/kubidm/target/release/librlm_kanidm.so /src/kubidm/target/release/rlm_kanidm.so && \
    sccache -s

# ======================
FROM repos AS final

ARG RADIUS_USER=radiusd
EXPOSE 1812 1813
ENV KUBIDM_CONFIG_FILE="/data/radius.toml"

RUN \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    freeradius \
    freeradius-utils \
    libfreeradius3 \
    openssl && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/log/radius /var/lib/nologin

ADD  rlm_kanidm/container/mods-available/ /etc/raddb/mods-available/
COPY rlm_kanidm/container/sites-available/ /etc/raddb/sites-available/

# Enable the native kanidm module and check-eap-tls virtual server.
RUN mkdir -p /etc/raddb/mods-enabled /etc/raddb/sites-enabled && \
    ln -s /etc/raddb/mods-available/kanidm_rust /etc/raddb/mods-enabled/kanidm && \
    ln -s /etc/raddb/sites-available/check-eap-tls /etc/raddb/sites-enabled/check-eap-tls

COPY --from=builder /src/kubidm/target/release/rlm_kanidm.so /usr/lib/freeradius/rlm_kanidm.so
COPY --from=builder /src/kubidm/target/release/kanidm_radiusd /usr/local/bin/kanidm_radiusd

# # disable auth via methods we don't support!
RUN rm -f /etc/raddb/mods-available/sql && \
    rm -f /etc/raddb/mods-enabled/{passwd,totp}

# Allows the radiusd user to write to the directory
RUN chown -R $RADIUS_USER:$RADIUS_USER /etc/raddb/ && \
    mkdir -p /etc/raddb/certs && \
    chmod 775 /etc/raddb/certs && \
    chmod 640 /etc/raddb/clients.conf

RUN mkdir /data && chown radiusd /data && \
    mkdir -p /etc/raddb/certs/ && chmod a+r /etc/raddb/certs/ -R
USER $RADIUS_USER

CMD [ "/usr/local/bin/kanidm_radiusd" ]

