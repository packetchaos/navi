FROM ubuntu:20.04

RUN apt-get update && apt-get install -y python3-pip && apt-get install -y netcat && apt-get install -y locales
RUN rm -rf /var/lib/apt/lists/*
RUN localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
RUN pip install requests
RUN pip install click
RUN pip install pandas
RUN pip install xlrd
RUN pip install pytenable
RUN pip install navi-pro

ENV LANG=en_US.utf8

ENV PATH="$PATH:/usr/bin/env/:/usr/src/app"

EXPOSE 8000

WORKDIR /usr/src/app
