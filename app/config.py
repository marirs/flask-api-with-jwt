"""
Desc: Skeleton app to access API's with JWT tokens
Author: [marirs,]
version: 1.0
"""
import os


basedir = os.path.abspath(os.path.dirname(__file__))


def check_dirs_if_exists(*args):
    """
    Validate the given directories exists. If the given directories
    do not exist, then creates them.
    :param args: dir1, dir2, dir3, etc, ...
    :return: None. (creates directories if they do not exist)
    """
    for arg in args:
        if not os.access(arg, os.F_OK):
            print("{} does not exist; creating...".format(arg))
            os.makedirs(arg)


check_dirs_if_exists(os.path.join(basedir, 'db'))


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'pj6(vi3o1ljas*61+lh8vpy4l=37ig#r!4pmf)!-1bkgc*y-@z')
    SECURITY_PASSWORD_SALT = os.getenv('SECURITY_PASSWORD_SALT', 'WkAxOgfeJ5rFj3uQvEsMpoC9SnhL1Gca_VEIO8jw7esQ3ltKxDXUr')
    DEBUG = False

    # flask-security settings
    SEND_REGISTER_EMAIL = False
    SECURITY_CONFIRMABLE = False
    SECURITY_REGISTERABLE = False
    SECURITY_TRACKABLE = True
    SECURITY_USER_IDENTITY_ATTRIBUTES = ['username', 'email']
    SECURITY_PASSWORD_HASH = 'pbkdf2_sha512'
    ADMIN_ROLE = 'Admin'


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'db', 'APIAccess.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'postgres://username:password@localhost:5432/apiaccess'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


key = Config.SECRET_KEY
