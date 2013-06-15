ADMINS = (
   #('Joe Admin', 'joeadmin@example.com'),
)

DATABASES = {
   'default': {
       'ENGINE': 'django.db.backends.postgresql_psycopg2',
       'NAME': 'ansibleworks',
       'USER': 'ansibleworks',
       'PASSWORD': 'AWsecret',
       'HOST': '',
       'PORT': '',
   }
}

STATIC_ROOT = '/var/lib/ansibleworks/public/static'

PROJECTS_ROOT = '/var/lib/ansibleworks/projects'

SECRET_KEY = file('/etc/ansibleworks/SECRET_KEY', 'rb').read().strip()

ALLOWED_HOSTS = ['*']

LOGGING['handlers']['syslog'] = {
    'level': 'ERROR',
    'filters': ['require_debug_false'],
    'class': 'logging.handlers.SysLogHandler',
    'address': '/dev/log',
    'facility': 'local0',
    'formatter': 'simple',
}

SERVER_EMAIL = 'root@localhost'
DEFAULT_FROM_EMAIL = 'webmaster@localhost'
EMAIL_SUBJECT_PREFIX = '[AnsibleWorks] '

EMAIL_HOST = 'localhost'
EMAIL_PORT = 25
EMAIL_HOST_USER = ''
EMAIL_HOST_PASSWORD = ''
EMAIL_USE_TLS = False
