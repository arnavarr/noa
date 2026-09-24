FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      dnsmasq dnsutils ca-certificates unzip curl && rm -rf /var/lib/apt/lists/*
ARG ZET_ARCH=arm64
ADD https://github.com/openziti/ziti-tunnel-sdk-c/releases/download/v1.15.1/ziti-edge-tunnel-Linux_${ZET_ARCH}.zip /tmp/zet.zip
RUN unzip /tmp/zet.zip -d /usr/local/bin && chmod +x /usr/local/bin/ziti-edge-tunnel
COPY dnsmasq-wild.conf /etc/dnsmasq.d/wild.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
