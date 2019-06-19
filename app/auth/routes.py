"""
Auth Routes
Desc: Skeleton app to access API's with JWT tokens
Author: [marirs,]
version: 1.0
"""
import app
import datetime
import jwt

from flask import Blueprint, request, jsonify, make_response
from werkzeug.security import generate_password_hash
from flask_login.signals import user_logged_in
from flask_security import user_registered

from app import user_datastore, db
from app.model import User, TrackLogin
from app.config import key as SECRET_KEY
from app.config import Config

from functools import wraps

auth = Blueprint('auth', __name__)
token_expiration_mins = 5


def requires_token(f):
    """
    Token Check decorator to be reused in other models
    :param f:
    :return:
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'status': 'Invalid Header', 'message': 'Missing x-access-token header'}), 401

        try:
            data = jwt.decode(token, SECRET_KEY)
            current_user = User.query.filter_by(id=data['id']).first()
            roles = data['roles']
        except:
            return jsonify({'status': 'Failure', 'message': 'Authentication fail'}), 401

        return f(current_user, roles, *args, **kwargs)
    return decorated


def requires_admin(f):
    """
    Admin check decorator to be reused on other models.
    :param f:
    :return:
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        roles = kwargs.get('roles', args[-1])
        if Config.ADMIN_ROLE in roles:
            return f(*args, **kwargs)
        return jsonify({'status': 'Forbidden', 'message': 'Admin required to access this resource.'}), 403
    return decorated


def make_jwt(user_id):
    """
    Creates the JWT Token using user_id, roles & SECRET_KEY
    :return: jwt token
    """
    session = db.session()
    user_obj = session.query(User).filter_by(id=user_id).first()
    roles = [role.name for role in user_obj.roles]
    expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=token_expiration_mins)
    token = jwt.encode({'id': user_id, 'roles': roles, 'exp': expiry}, SECRET_KEY)

    return token


@auth.route('/user/login', methods=['GET', 'POST'])
def login_user():
    """
    A post request with a valid name/pass combination made to this route or
    Basic Realm login method to this route
    Returns:
        - A signed json web token for accessing protected resources
    """
    if request.method == 'GET':
        # Basic Realm
        credentials = request.authorization
        if not credentials or not credentials.username or not credentials.password:
            return make_response("Missing headers/parameters", 401, {'WWW-Authenticate': 'Basic realm="Please supply correct credentials"'})

        # query user
        user = User.query.filter_by(username=credentials.username).first()

        if not user:
            return make_response("User not found", 401, {'WWW-Authenticate': 'Basic realm="Please supply correct credentials"'})

        if user.check_password(credentials.password):
            token = make_jwt(user.id)

            return jsonify({'access_token': token.decode('UTF-8')})

        return make_response("Authentication failed", 401, {'WWW-Authenticate': 'Basic realm="Please supply correct credentials"'})

    elif request.method == 'POST':
        # JSON Post
        credentials = request.get_json()
        dict_keys = list(credentials.keys())
        if 'username' not in dict_keys or 'password' not in dict_keys:
            return jsonify({'message': 'Missing username/password'}), 401

        # query user
        user = User.query.filter_by(username=credentials['username']).first()

        if not user:
            return jsonify({'message': 'User not found'})

        if user.check_password(credentials['password']):
            token = make_jwt(user.id)

            return jsonify({'access_token': token.decode('UTF-8')})

        return jsonify({'status': 'Failure', 'message': 'incorrect user/password combination'})


@auth.route('/user/new', methods=['POST'])
@requires_token
@requires_admin
def new_user(current_user, roles):
    """
    Protected Route to Create a new user (requires JWT)
    Send a post request with a json payload consisting of a username and a password
    Returns:
        - 200 status code and the newly registered username and password
    """
    # load data from request
    add_user = request.get_json()

    # hash password and save user to db
    hashed_password = generate_password_hash(add_user['password'], method='pbkdf2:sha512')
    new_user = User(username=add_user['username'], password=hashed_password, email=add_user['email'])
    db.session.add(new_user)
    db.session.commit()

    response_dict = {
        "status": "Success",
        "id": new_user.id,
        "name": add_user['username']
    }
    return jsonify({"data": response_dict})


@auth.route('/user/list', methods=['GET'])
@requires_token
@requires_admin
def list_users(current_user, roles):
    """
    Protected Route to List all users in DB (requires JWT)
    :param current_user:
    :return:
    """
    users = User.query.all()

    resp = {
        "data": [

        ]
    }
    for user in users:
        resp['data'].append({'id': user.id, 'name': user.username})

    return jsonify(resp)


# Signals
@user_registered.connect_via(app)
def _post_user_registration(app, **other_fields):
    """Handler to handle post user registration
    """
    default_role = user_datastore.find_role("User")
    user_datastore.add_role_to_user(other_fields.get('users'), default_role)
    db.session.commit()


@user_logged_in.connect_via(app)
def _post_user_login(app, **other_fields):
    """Handler to handle post user logs in
    update details
    """
    user_id = other_fields.get('user').get_id()
    user = User.query.filter_by(id=user_id).first()

    remote_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    tracked = TrackLogin(ip_address=remote_ip, user_id=user_id, login_date=datetime.datetime.utcnow())
    user.track_login.append(tracked)
    db.session.commit()
