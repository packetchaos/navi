# navi CLI — Tenable Vulnerability Management
FROM python:3.12-slim-bookworm

# Locale (pandas/navi expect UTF-8) + netcat in one cached layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-openbsd locales \
    && sed -i '/en_US.UTF-8/s/^# //' /etc/locale.gen \
    && locale-gen \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

# Let navi-pro pull its own deps 
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir navi-pro

EXPOSE 8000
WORKDIR /usr/src/app
