# navi + navi-mcp — Tenable Vulnerability Management CLI and MCP server
# Base: Ubuntu 24.04 LTS (ships Python 3.12 natively, free/open).
# Build context = the folder containing the navi-mcp repo (server/, skills/, tools/).

FROM ubuntu:24.04

# Non-interactive apt + sane locale (navi/pandas expect UTF-8)
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.12 \
        python3.12-venv \
        python3-pip \
        git \
        netcat-openbsd \
        locales \
        ca-certificates \
        curl \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

# Isolated virtualenv (Ubuntu 24.04 enforces PEP 668; a venv avoids
# --break-system-packages and keeps navi's deps off the system Python).
RUN python3.12 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# navi (PyPI: navi-pro) + its runtime deps + the MCP SDK for the server.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
        requests \
        click \
        pandas \
        xlrd \
        pytenable \
        navi-pro \
        mcp

# Copy the navi-mcp repo (server.py + skills + tools) into the image.
COPY .. /app

# Runtime config for the MCP server (see navi-mcp README env table).
#   NAVI_SKILL_DIR       -> unpacked skills/ so navi://skill/... resources resolve
#   NAVI_WORKDIR         -> where navi.db and CSV exports live (mounted volume)
#   NAVI_BIN             -> absolute path to the navi binary in the venv
#   NAVI_MCP_ALLOW_WRITES-> 1 enables tagging/ACR/scan/delete tools (still need confirm=True per call)
# NOTE: the MCP server lives inside the navi-mcp-suite/ subfolder of the navi repo.
ENV NAVI_SKILL_DIR=/app/navi-mcp-suite/skills \
    NAVI_WORKDIR=/data \
    NAVI_BIN=/opt/venv/bin/navi \
    NAVI_MCP_ALLOW_WRITES=1

# navi.db is created in the working directory — keep it on a mounted volume.
WORKDIR /data
VOLUME ["/data"]

# Streamable HTTP transport for the MCP server.
EXPOSE 8000

# Start the MCP server over HTTP on :8000.
# API keys are NOT baked in — set them once into the mounted volume with:
#   docker run --rm -v navi-data:/data navi-mcp:latest navi config keys --a <ACCESS> --s <SECRET>
# then do the first sync (long-running, run it on the CLI, not via MCP):
#   docker run --rm -v navi-data:/data navi-mcp:latest navi config update full
CMD ["python", "/app/navi-mcp-suite/server/server.py", "--http"]
