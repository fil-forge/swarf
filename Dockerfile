FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*
COPY swarf /usr/bin/swarf
EXPOSE 8080
ENTRYPOINT ["/usr/bin/swarf", "serve"]
