FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

RUN npm install --global @informalsystems/quint@0.32.0

ENTRYPOINT ["quint"]
