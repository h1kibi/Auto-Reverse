FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    file \
    strace \
    ltrace \
    libc6 \
    libstdc++6 \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 analyst

USER analyst
WORKDIR /work

ENTRYPOINT ["/bin/bash", "-lc"]
