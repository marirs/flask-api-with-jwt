"""
Desc: Skeleton app to access API's with JWT tokens
Author: [marirs,]
version: 1.0
"""
from werkzeug.security import check_password_hash
from flask_security import RoleMixin
from flask_login import UserMixin

from app import db
from uuid import uuid4
from datetime import datetime 


# many-to-many relationship between Users and Roles
roles_users = db.Table('roles_users',
                       db.Column('user_id', db.String(32), db.ForeignKey('users.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('roles.id')))


class Role(RoleMixin, db.Model):
    """Roles
    """
    __tablename__ = 'roles'

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __str__(self):
        """enable human-readable values for the Role when editing a User
        if __str__ does not work, try __unicode__ (py 2.7 perhaps)
        """
        return self.name

    def __hash__(self):
        """required to avoid the exception
        TypeError: unhashable type: 'Role' when saving a User
        """
        return hash(self.name)


class User(UserMixin, db.Model):
    """Users
    """
    __tablename__ = 'users'

    id = db.Column(db.String(32), default=lambda: str(uuid4().hex), primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(80))
    email = db.Column(db.String(60), unique=True)
    active = db.Column(db.Boolean(), default=1)
    created_date = db.Column(db.DateTime(), unique=False, default=datetime.utcnow())
    last_login_ip = db.Column(db.String(18), unique=False)
    current_login_ip = db.Column(db.String(18), unique=False)
    last_login_at = db.Column(db.DateTime, unique=False)
    current_login_at = db.Column(db.DateTime, unique=False)
    login_count = db.Column(db.Integer(), unique=False)
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    track_login = db.relationship('TrackLogin', backref='linkeduser', cascade='all,delete')

    def as_dict(self):
        """custom deserializer for complex objects when needed
        """
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def has_role(self, role):
        """return the roles of a logged in user
        """
        return role in self.roles


class TrackLogin(db.Model):
    """Track all user logins
    """
    __tablename__ = 'track_logins'

    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.String(32), db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(20), unique=False)
    login_date = db.Column(db.DateTime, unique=False)

    def as_dict(self):
        """custom deserializer for complex objects when needed
        """
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}
