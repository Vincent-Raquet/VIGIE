# syntax=docker/dockerfile:1
# Image de production de Vigie. Contexte de construction : dist/ (deploy/build.sh) — le wheel
# et la liste figée des dépendances avec empreintes ; aucun fichier du dépôt n'y entre, donc
# ni .env.local ni config réelle (SECURITY.md C7).
ARG PYTHON_IMAGE=python:3.13-slim-trixie

FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1
COPY requirements.txt vigie-*.whl /tmp/dist/
RUN python -m venv /opt/vigie \
 && /opt/vigie/bin/pip install --require-hashes -r /tmp/dist/requirements.txt \
 && /opt/vigie/bin/pip install --no-deps /tmp/dist/vigie-*.whl

FROM ${PYTHON_IMAGE}
ARG VIGIE_RELEASE=inconnue
LABEL org.opencontainers.image.title="vigie" \
      org.opencontainers.image.version="${VIGIE_RELEASE}"
# tzdata : fuseaux horaires (zoneinfo) ; rien d'autre que l'image Python de base.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/vigie /opt/vigie
ENV PATH=/opt/vigie/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Europe/Brussels \
    VIGIE_CONFIG=/etc/vigie/vigie.toml \
    VIGIE_LOG_LEVEL=INFO \
    CREDENTIALS_DIRECTORY=/run/secrets
# Compte imposé par compose.yaml (UID des comptes vigie-* de l'hôte, pour l'authentification
# peer de PostgreSQL) ; à défaut, jamais root.
USER 65534:65534
ENTRYPOINT ["vigie"]
CMD ["--help"]
