# Flask Skeleton App to access API's with JWT

Skeleton application to access api endpoints with JWT

#### Requirements
- Python 3

#### Deployment

#### Setting up the virtual environment
Python 3.x virtual environment
```bash
mkvirtualenv --python=`which python3` venv_name
cd /path/to/project/
setvirtualenvproject
```

Installing the pip requirements
```bash
pip install -r requirements
```

Setting up PostgresSQL (if postgres)
```bash
psql

CREATE DATABASE adbname ENCODING 'UTF-8';
CREATE USER appuser WITH PASSWORD 'AC0mp13XPa55w0rd';
GRANT ALL PRIVILEGES ON DATABASE adbname to appuser;
```

DB Init & Migrations
```bash
flask db init
flask db migrate
flask db upgrade
```

Creating default Roles
```bash
flask create_roles
```

Creating the super user
```bash
flask create_super name name@email.com
```
---
#### *Running the app*
```bash
flask run
```

#### *Accessing the app*
```bash
http://localhost:5000
```

---
#### Auth Endpoints
- /auth/user/new : Create new user (requires the JWT auth)
- /auth/user/list : List all users (requires the JWT auth)
- /auth/user/login : Login to generate a JWT

#### Service Endpoints
- /api/ : Create your API's here (requires the JWT auth)

---
Author: Sriram