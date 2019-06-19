"""
Desc: Skeleton app to access API's with JWT tokens
Author: [marirs,]
version: 1.0
"""
import click
from werkzeug.security import generate_password_hash
from flask import Flask, Blueprint
from flask_security import SQLAlchemyUserDatastore, Security
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate

from app.config import *

# init: flask app
app = Flask(__name__)
app.config.from_object(DevelopmentConfig)
app.url_map.strict_slashes = False

db = SQLAlchemy(app)
flask_bcrypt = Bcrypt()
migrate = Migrate(app, db)

from app.model import *

# flask security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

flask_bcrypt.init_app(app)
db.init_app(app)

from app.auth.routes import auth as auth_blueprint
from app.api.routes import api as api_blueprint

# Blueprints
app.register_blueprint(api_blueprint, url_prefix='/api')
app.register_blueprint(auth_blueprint, url_prefix='/auth')


# Context processors
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


# Cli commands
@app.cli.command('create_roles')
def create_default_roles():
    """Create default roles
    """
    user_datastore.find_or_create_role(name='Admin', description='Administrators')
    user_datastore.find_or_create_role(name='User', description='Users')

    db.session.commit()
    print("Default Roles created.")


@app.cli.command('create_super')
@click.argument('username')
@click.argument('email')
def create_superuser(username, email):
    """Create superuser
    """
    import getpass
    from datetime import datetime

    try:
        password = getpass.getpass('Enter your password: ')
        while password is '':
            print('Password cannot be blank')
            password = getpass.getpass('Enter your password: ')
        while len(password) < 8:
            print('Password should be 8 or more chars')
            password = getpass.getpass('Enter your password: ')
        hashed_pass = generate_password_hash(password, method='pbkdf2:sha512')

        user_datastore.create_user(username=username, email=email, password=hashed_pass, created_date=datetime.utcnow())
        user_datastore.add_role_to_user(email, 'Admin')
        db.session.commit()

        print('User created successfully')
    except IntegrityError:
        db.session.rollback()
        print('User with a similar email already exists.')
