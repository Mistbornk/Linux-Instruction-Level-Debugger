FROM ubuntu:24.04

# SDB traces an x86-64 Linux kernel, not an emulated amd64 userspace on ARM.
RUN test "$(dpkg --print-architecture)" = amd64 || \
    { echo 'Use an x86-64 Linux host or a full x86-64 Linux VM.' >&2; exit 1; }
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build libcapstone-dev python3 binutils && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/sdb
COPY . .
CMD ["bash"]
