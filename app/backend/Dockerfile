FROM python:3.11-slim-bookworm

# Ghidra 11.x runs on Java 17+; JRE is enough for analyzeHeadless (JDK not required).
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    wget \
    unzip \
    ca-certificates \
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
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
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
