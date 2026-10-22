# syntax=docker/dockerfile:1
# Proxy sortant de Vigie (SECURITY.md C6) : Squid de Debian 13, configuration montée par
# compose.yaml. Lancé en avant-plan sous le compte proxy (UID 13 de Debian), sans privilège.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends squid \
 && rm -rf /var/lib/apt/lists/*
USER proxy
ENTRYPOINT ["squid", "-N", "-f", "/etc/squid/squid.conf"]
