"""
API Routes
Desc: Skeleton app to access API's with JWT tokens
Author: [marirs,]
version: 1.0
"""
import os
from flask import Blueprint, request, jsonify

from app import db
from app.auth.routes import requires_token
from uuid import uuid4


api = Blueprint('api', __name__)

@api.route('/', methods=['POST'])
@requires_token
def api_home(current_user, roles):
    """
    Sample Home protected API endpoint
    :param current_user:
    :param roles:
    :return:
    """
    return jsonify({'message': 'api home', 'status': 'success'}), 200