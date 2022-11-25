FROM python:3.8

ENV PYTHONUNBUFFERED 1

RUN \
    mkdir -p /srv/redifod && \
    cd /srv/redifod

WORKDIR /srv/redifod/

RUN \
    apt-get update && \
    apt-get install -y lsb-release apt-utils postgresql-client nano \
        libxml2-dev libxslt-dev gcc python-dev dnsutils openssh-server && \
    apt-get clean all

RUN git clone --depth 1 https://code.grnet.gr/git/nxpy ~/nxpy

RUN python3.8 -m pip install --upgrade pip

RUN \
    curl -LO https://github.com/leopoul/ncclient/archive/refs/tags/v0.6.3.zip && \
    unzip v0.6.3.zip && \
    cd ncclient-0.6.3 && \
    python3.8 -m pip install .

COPY ./requirements.txt /srv/redifod/requirements.txt

RUN python3.8 -m pip install -r requirements.txt

COPY . /srv/redifod/

ENV PATH="${PATH}:/usr/lib/postgresql/13/bin/psql"

COPY ./id_rsa ~/.ssh/id_rsa

EXPOSE 8000
