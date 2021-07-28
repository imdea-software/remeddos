#!/bin/bash
#!/bin/sh

export LC_ALL="C"

#apt-get -y install apache2 
#apt-get -y install libapache2-mod-shib2
#apt-get -y install perl libcgi-pm-perl

[ -z "$NOAPT" ] && apt-get -y install apache2 libapache2-mod-shib2 perl libcgi-pm-perl

[ -z "$NOMOD" ] && a2enmod proxy
[ -z "$NOMOD" ] && a2enmod proxy_http
[ -z "$NOMOD" ] && a2enmod cgi

# 

basedir="/srv/flowspy"
basedir2="$basedir/inst/apache_shib"

#cd /srv/flowspy/ || exit 3
cd "$basedir" || exit 3

#cp -uva shibboleth_inst/inst/etc/apache2/ shibboleth_inst/inst/etc/shibboleth/ /etc/

echo 1>&2
#cp -uva shibboleth_inst/inst/etc/apache2/ /etc/
#cd ./shibboleth_inst/inst/etc/apache2/ && cp -uva --parents -t /etc/apache2/ .
#cd "$basedir/shibboleth_inst/inst/etc/apache2/" && cp -uva --parents -t /etc/apache2/ $(cat "$basedir/shibboleth_inst/etc-apache-diff.list.filtered2")
(cd "$basedir2/files.inst/etc/apache2/" && cp -fva --parents -t /etc/apache2/ $(cat "$basedir2/files.inst/etc-apache-diff.list.filtered2"))

echo 1>&2
#cp -uva shibboleth_inst/inst/etc/shibboleth/ /etc/
(cd "$basedir2/files.inst/etc/shibboleth/" && cp -fva --parents -t /etc/shibboleth/ $(cat "$basedir2/files.inst/etc-shibboleth-diff.list.filtered2"))

##

echo 1>&2
#cp shibboleth_inst/inst/srv/flowspy/flowspy/settings.py flowspy/settings.py
cp -fv "$basedir2/files.inst/srv/flowspy/flowspy/settings.py" flowspy/settings.py

echo 1>&2
(cd /etc/shibboleth/ && ./keygen.sh)

echo 1>&2
# -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/"
(cd /etc/apache2/ && openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 -keyout mysitename.key -out mysitename.crt)

##

echo 1>&2
hostname test-fod.geant.net

##

/etc/init.d/shibd restart

/etc/init.d/apache2 restart




