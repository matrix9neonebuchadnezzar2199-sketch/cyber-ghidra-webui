# Ghidra 11.3.1+ requires Java 21; LaunchSupport / analyzeHeadless need a full JDK (javac). Temurin multistage.
FROM eclipse-temurin:21-jdk-jammy AS java21

FROM python:3.11-slim-bookworm
COPY --from=java21 /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    unzip \
    ca-certificates \
    p7zip-full \
    && rm -rf /var/lib/apt/lists/*

ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_DATE=20250219
RUN wget -q \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
    -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && rm /tmp/ghidra.zip \
    && ln -sf "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra

ENV GHIDRA_HOME=/opt/ghidra
ENV _JAVA_OPTIONS="-Xmx4g"

WORKDIR /app

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/input /app/output /app/queue/pending /app/queue/processing /app/queue/done /tmp/ghidra_projects /workspace/ghidra_projects

EXPOSE 8000

CMD ["/opt/venv/bin/uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
