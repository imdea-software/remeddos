FROM python:3.6

ENV PYTHONUNBUFFERED 1

COPY . /srv/redifod/

WORKDIR /srv/redifod/


RUN mkdir -p /home/remedios/


RUN useradd -u 6678 remedios


RUN chown -R remedios /home/remedios/
RUN mkdir -p /etc/redis/ && \
            touch /etc/redis/redis.conf
RUN chown -R remedios /etc/redis/ 
RUN echo "vm.overcommit_memory = 1" >> /etc/sysctl.conf

COPY ./id_rsa /home/remedios/.ssh/id_rsa 

RUN mkdir -p /var/log/fod/ && \
    mkdir /var/log/fod/error.log && \
    cd /var/log/fod && \
    touch celery_jobs.log poller.log && \
    cd error.log && \
    touch celery_jobs.log touch poller.log 

RUN chown remedios /var/log/fod/error.log && \
        chown remedios  /var/log/fod/celery_jobs.log && \
        chown remedios /var/log/fod/poller.log



RUN cd /srv/redifod/ 
RUN python3.6 -m pip install --upgrade pip
RUN apt-get update && apt-get install -y lsb-release apt-utils && apt-get clean all
RUN apt-get update && apt-get -y install postgresql-client nano
RUN apt-get install -y libxml2-dev libxslt-dev gcc python-dev dnsutils
RUN apt-get -y install openssh-server 

RUN cd ~ && \
    git clone https://github.com/leopoul/ncclient.git && \
    cd ncclient && \
    python3.6 setup.py install
RUN cd ~ && \
    git clone https://code.grnet.gr/git/nxpy 

RUN cd /srv/redifod/ && \
    python3.6 -m pip install -r requirements.txt 



RUN export PATH=$PATH:/usr/lib/postgresql/13/bin/psql



EXPOSE 8000
