FROM python:3.6

ENV PYTHONUNBUFFERED 1

COPY . /srv/redifod/
WORKDIR /srv/redifod/

RUN cd /srv/redifod/ 
RUN python3.6 -m pip install --upgrade pip
RUN apt-get update && apt-get install -y lsb-release apt-utils && apt-get clean all
RUN sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list' 
RUN wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
RUN apt-get update && apt-get -y install postgresql
RUN apt-get install -y libxml2-dev libxslt-dev gcc python-dev
RUN cd ~ && \
    git clone https://github.com/leopoul/ncclient.git && \
    cd ncclient && \
    python3.6 setup.py install
RUN cd ~ && \
    git clone https://code.grnet.gr/git/nxpy 

RUN cd /srv/redifod/ && \
    python3.6 - m pip install paramiko && \
    python3.6 -m pip install -r requirements.txt 

RUN mkdir -p /var/log/fod && \
    mkdir /var/log/fod/error.log && \
    cd /var/log/fod && \
    touch celery_jobs.log poller.log && \
    cd error.log && \
    touch celery_jobs.log touch poller.log 



RUN export PATH=$PATH:/usr/lib/postgresql/13/bin/psql

EXPOSE 8000

FROM ubuntu:18.04

RUN \
      apt-get update && apt-get install -y \
      # general tools
      git \
      cmake \
      build-essential \
      vim \
      supervisor \
      # libyang
      libpcre2-dev \
      pkg-config \
      # sysrepo
      libavl-dev \
      libev-dev \
      libprotobuf-dev \
      protobuf-compiler \
      clang \
      # netopeer2 \
      libssh-dev \
      libssl-dev \
      # bindings
      swig \
      python-dev

# add netconf user
RUN \
      adduser --system netconf && \
      echo "netconf:netconf" | chpasswd

# generate ssh keys for netconf user
RUN \
      mkdir -p /home/netconf/.ssh && \
      ssh-keygen -A && \
      ssh-keygen -t dsa -P '' -f /home/netconf/.ssh/id_dsa && \
      cat /home/netconf/.ssh/id_dsa.pub > /home/netconf/.ssh/authorized_keys

# use /opt/dev as working directory
RUN mkdir /opt/dev
WORKDIR /opt/dev


# libyang
RUN  git clone https://github.com/CESNET/libyang.git
RUN  cd libyang  
RUN  mkdir build && cd build 
RUN  cmake -D ENABLE_BUILD_TESTS=OFF /opt/dev/libyang/
RUN  make -j2 
RUN  make install 
RUN  ldconfig
RUN  rm -f CMakeCache.txt

# sysrepo
RUN  cd /opt/dev/
RUN  git clone -b legacy https://github.com/sysrepo/sysrepo.git
RUN  cd sysrepo && mkdir build && cd build 
RUN  cmake -D REQUEST_TIMEOUT=60 -D REPOSITORY_LOC:PATH=/etc/sysrepo /opt/dev/sysrepo/ 
RUN  make -j2
RUN  make install 
RUN  ldconfig
RUN  rm -f CMakeCache.txt


# libnetconf2
RUN  cd /opt/dev/
RUN  git clone -b legacy https://github.com/CESNET/libnetconf2.git 
RUN  cd libnetconf2 && mkdir build && cd build 
RUN  cmake -D CMAKE_BUILD_TYPE:String="Debug" -D ENABLE_BUILD_TESTS=OFF /opt/dev/libnetconf2/ 
RUN  make -j2 
RUN  make install 
RUN  ldconfig
RUN  rm -f CMakeCache.txt

# netopeer2
RUN  cd /opt/dev/ 
RUN  git clone -b legacy https://github.com/CESNET/Netopeer2.git 
RUN  cd Netopeer2/server && mkdir build && cd build 
RUN  cmake -DCMAKE_BUILD_TYPE:String="Debug" /opt/dev/libnetconf2/Netopeer2/cli 
RUN  make -j2 
RUN  make install 
RUN  cd ../../cli && mkdir build && cd build 
RUN  cmake -DCMAKE_BUILD_TYPE:String="Debug" .. 
RUN  make -j2
RUN  make install
RUN  rm -f CMakeCache.txt




ENV EDITOR vim
EXPOSE 830

COPY ./router-container/configuration.yang /opt/dev/configuration.yang
COPY ./router-container/junos-extension.yang /opt/dev/junos-extension.yang
RUN /usr/local/bin/sysrepoctl -i -g /opt/dev/configuration.yang
RUN /usr/local/bin/sysrepoctl -i -g /opt/dev/junos-extension.yang

COPY ./router-container/supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]