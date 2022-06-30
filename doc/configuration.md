 Time to configure flowspy.

First of all you have to copy the dist files to their proper position:

	# cd /srv/flowspy/flowspy
	# cp settings.py.dist settings.py
	# cp urls.py.dist urls.py

Then, you have to edit the settings.py file to correspond to your needs. The settings one has to focus on are:

## Settings.py
Its time to configure `settings.py` in order to connect flowspy with a database, a network device and a broker.

So lets edit settings.py file.

It is strongly advised that you do not change the following to False
values unless, you want to integrate REMeDDoS with you CRM or members
database. This implies that you are able/have the rights to create
database views between the two databases:

    PEER_MANAGED_TABLE = True
    PEER_RANGE_MANAGED_TABLE = True
    PEER_TECHC_MANAGED_TABLE = True

By doing that the corresponding tables as defined in peers/models will
not be created. As noted above, you have to create the views that the
tables will rely on.

### Administrators

	ADMINS: set your admin name and email (assuming that your server can send notifications)

### Secret Key
Please put a random string in `SECRET_KEY` setting.
Make this *unique*, and don't share it with anybody. It's the unique identifier of this instance of the application.

### Allowed hosts
A list of strings representing the host/domain names that this Django site can serve. This is a security measure to prevent an attacker from poisoning caches and password reset emails with links to malicious hosts by submitting requests with a fake HTTP Host header, which is possible even under many seemingly-safe webserver configurations.

For example:

	ALLOWED_HOSTS = ['*']

### Protected subnets
Subnets for which source or destination address will prevent rule creation and notify the `NOTIFY_ADMIN_MAILS`.

	PROTECTED_SUBNETS = ['10.10.0.0/16']


### Database
`DATABASES` should contain the database credentials:

	DATABASES = {
	    'default': {
	        'ENGINE': 'django.db.backends.postgresql_psycopg2',
	        'NAME': 'flowspy',
	        'USER': '<db user>',
	        'PASSWORD': '<db password>',
	        'HOST': '<db host>',
	        'PORT': '',
	    }
	}

### Localization
In case you want to add another language, or remove one of the existing, you can change the `LANGUAGES`
variable and follow [django's localization documentation](https://docs.djangoproject.com/en/1.4/topics/i18n/translation/#localization-how-to-create-language-files)

You might want to change `TIME_ZONE` setting too. Here is a [list](http://en.wikipedia.org/wiki/List_of_tz_database_time_zones)


### Cache
Flowspy uses cache in order to be fast. We recomend the usage of memcached, but
any cache backend supported by django should work fine.

	CACHES = {
	    'default': {
	        'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
	        'LOCATION': '127.0.0.1:11211',
	    }
	}

### Network device access
We have to inform django about the device we set up earlier.

	NETCONF_DEVICE = "device.example.com"
	NETCONF_USER = "<netconf user>"
	NETCONF_PASS = "<netconf password>"
	NETCONF_PORT = 830




### Notifications
Outgoing mail address and prefix.

	SERVER_EMAIL = "Example REMeDDoS Service <noreply@example.com>"
	EMAIL_SUBJECT_PREFIX = "[REMeDDoS] "
	NOTIFY_ADMIN_MAILS = ["admin@example.com"]


If you have not installed an outgoing mail server you can always use your own account (either corporate or gmail, hotmail ,etc) by adding the
following lines in settings.py:

    EMAIL_USE_TLS = True #(or False)
    EMAIL_HOST = 'smtp.example.com'
    EMAIL_HOST_USER = 'username'
    EMAIL_HOST_PASSWORD = 'yourpassword'
    EMAIL_PORT = 587 #(outgoing)

### Whois servers
Add two whois servers in order to be able to get all the subnets for an AS.

	PRIMARY_WHOIS = 'whois.example.com'
	ALTERNATE_WHOIS = 'whois.example.net'

### Branding
Fill your company's information in order to show it in flowspy.

	BRANDING = {
	    'name': 'Example.com',
	    'url': 'https://example.com',
	    'footer_iframe': 'https://example.com/iframes/footer/',
	    'facebook': '//facebook.com/example.com',
	    'twitter': '//twitter.com/examplecom',
	    'phone': '800-12-12345',
	    'email': 'helpdesk@example.com',
	    'logo': 'logo.png',
	    'favicon': 'favicon.ico',
	}


### Syncing the database
To create all the tables needed by REMeDDoS we have to run the following commands:

	cd /srv/flowspy
	./manage.py syncdb --noinput
	./manage.py migrate

## Create a superuser
A superuser can be added by using the following command from `/srv/flowspy/`:

	./manage.py createsuperuser


## Propagate the flatpages
Inside the initial\_data/fixtures\_manual.xml file we have placed 4
flatpages (2 for Greek, 2 for English) with Information and Terms of
Service about the service. To import the flatpages, run from root
folder:

    python manage.py loaddata initial_data/fixtures_manual.xml

### Celery
Celery is a distributed task queue, which helps REMeDDoS run some async tasks, like applying a flowspec rule to a router.

`Note` In order to check if celery runs or even debug it, you can run:

	./manage.py celeryd --loglevel=debug


### Testing/Debugging
In order to see what went wrong you can check the following things.

#### Django
You can start the server manually by running:

	./manage.py runserver 127.0.0.1:8081

By doing so, you can serve your application like gunicord does just to test that its starting properly. This command should not be used in production!

Of course you have to stop gunicorn and make sure that port 8081 is free.

Start the gunicorn server: 

	docker-compose run --rm web gunicorn --bind 0.0.0.0:8000 flowspy.wsgi:application

## Usage

### Web interface
REMeDDoS comes with a web interface, in which one can edit and apply new routes.


### Docker - Commands
See what container are running:

	docker ps

Build your docker-compose:

	docker-compose build  // docker-compose up --build


Run all services at once:

	docker-compose up 

Run an specific service:

	docker-compose up <service_name>

Create a new container to run a command for a specific service, the container will cease to exist once the command
is executed. In order for this command to work, a cointainer must be already running so if I wanted to execute something within the web cointainer
it is mandatory that there's at least one web running.

	docker-compose run --rm <service_name> <command> Example: docker-compose run --rm web python3 manage.py shell

If for example you would like to open a bash terminal within a container that is already running the command is:

	docker exec -it <container_name> bash

	Ex: docker exec -it redifod_web_1 bash

Stop a running docker-compose service: 

	docker-compose stop 

	If you want to stop an specific service you would specify it: docker-compose stop <service_name>

Create a backup from the database 

		docker-compose run --rm web python3 manage.py dumpdata --format=json -o='<path>/<to_file>/<file_name>.json'
	
		Ex: docker-compose run --rm web python3 manage.py dumpdata --format=json -o='_backup/REM_REMEDIOS/_backup_test.json'

Create a back_up for an specific solution:

		docker-compose run --rm web python3 manage.py dumpdata <app_name>.<table_name> --format=json -o='<path>/<to_file>/<file_name>.json'

		Ex: docker-compose run --rm web python3 manage.py dumpdata flowspec.ROUTE_CV --format=json -o='_backup/CV/_backup1_test.json'
		

Load data from a backup copy:
		docker-compose run --rm web python3 manage.py loaddata <fixture>

		Ex: docker-compose run --rm web python3 manage.py loaddata /srv/redifod/_backup/REM_REMEDIOS/_backup_test.json

