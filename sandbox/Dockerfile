# AgentOS 沙箱执行镜像：ubuntu + 自研 llandlock（Landlock 策略编译目标）
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY llandlock.c /tmp/llandlock.c
RUN gcc -O2 -o /usr/local/bin/llandlock /tmp/llandlock.c && rm /tmp/llandlock.c
ENTRYPOINT ["/usr/local/bin/llandlock"]
