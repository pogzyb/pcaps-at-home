import os

##########################################
# Superset specific config
##########################################

ROW_LIMIT = 5000
SUPERSET_WEBSERVER_PORT = os.getenv('SUPERSET_PORT')

##########################################
# Flask App Builder configuration
##########################################

# Base directory
BASE_DIR = '/opt/superset'

# The file upload folder, when using models with files
UPLOAD_FOLDER = BASE_DIR + '/app/static/uploads/'

# The image upload folder, when using models with images
IMG_UPLOAD_FOLDER = BASE_DIR + '/app/static/uploads/'

# Your App secret key
SECRET_KEY = os.getenv('SUPERSET_SECRET_KEY')

# The SQLAlchemy connection string to your database backend
# This connection defines the path to the database that stores your
# superset metadata (slices, connections, tables, dashboards, ...).
# Note that the connection information to connect to the datasources
# you want to explore are managed directly in the web UI
SQLALCHEMY_DATABASE_URI = f'{os.getenv("SUPERSET_DATABASE_URI")}'
SQLALCHEMY_TRACK_MODIFICATIONS = True
CACHE_CONFIG = {
    'CACHE_TYPE': 'redis',
    'CACHE_DEFAULT_TIMEOUT': 300,
    'CACHE_KEY_PREFIX': 'superset_',
    'CACHE_REDIS_HOST': f'{os.getenv("REDIS_HOSTNAME")}',
    'CACHE_REDIS_PORT': int(os.getenv('REDIS_PORT')),
    'CACHE_REDIS_DB': 1,
    'CACHE_REDIS_URL': f'redis://{os.getenv("REDIS_HOSTNAME")}:{os.getenv("REDIS_PORT")}/1'
}

# Flask-WTF flag for CSRF
WTF_CSRF_ENABLED = True
# Add endpoints that need to be exempt from CSRF protection
WTF_CSRF_EXEMPT_LIST = []
# A CSRF token that expires in 1 year
WTF_CSRF_TIME_LIMIT = 60 * 60 * 24 * 365

# Set this API key to enable Mapbox visualizations
MAPBOX_API_KEY = ''