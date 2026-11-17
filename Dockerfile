FROM ubuntu:24.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY attacks/scenarios.py attacks/simulator.py /app/attacks/

FROM runtime AS simulator
RUN apt-get update && apt-get install -y --no-install-recommends netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
USER 10001:10001
CMD ["python3", "-m", "attacks.simulator"]

FROM runtime AS detector
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-bpfcc python3-yaml ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY agent/ /app/agent/
COPY rules/ /app/rules/
COPY dashboard/ /app/dashboard/
EXPOSE 8080
CMD ["python3", "-m", "agent.agent"]
