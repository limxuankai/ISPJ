import os 
import json
import sqlite3
import datetime

from flask import Flask, redirect, request, url_for,render_template,abort,flash
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests
from db import init_db_command
from user import User
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

app.logger.setLevel(logging.INFO)
for handler in app.logger.handlers[:]:
    app.logger.removeHandler(handler)
file_handler = RotatingFileHandler('app.log', mode='a', maxBytes=0, backupCount=0)
formatter = logging.Formatter('%(asctime)s: %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
app.logger.addHandler(file_handler)

app.logger.propagate = False

app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
GOOGLE_CLIENT_ID = "326380353762-pek05h1clqj4likpcjtqba5gdf831okv.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

login_manager = LoginManager()
login_manager.init_app(app)

try:
    init_db_command()
except sqlite3.OperationalError:
    app.logger.error("Error:sqlite3.OperationalError")

client = WebApplicationClient(GOOGLE_CLIENT_ID)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/',methods=['GET','POST'])
@app.route('/home',methods=['GET','POST'])
def home():
        app.logger.info('Guest has reached homepage')
        return render_template('home.html')

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/login")
def login():
    app.logger.info('Guest is trying to login')
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route('/login/callback', methods=['GET','POST'])
def callback():
    app.logger.info('Guest is authenticating on Google')
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    token_url, headers, body = client.prepare_token_request(
    token_endpoint,
    authorization_response=request.url,
    redirect_url=request.base_url,
    code=code
)
    token_response = requests.post(
    token_url,
    headers=headers,
    data=body,
    auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
)

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400
    user = User(
    id_=unique_id, name=users_name, email=users_email, profile_pic=picture
)
    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)
    login_user(user)
    return redirect(url_for("dashboard"))

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    app.logger.info(f'{current_user.name} has logged in')
    return render_template("dashboard.html")

@app.route("/logout")
@login_required
def logout():
    app.logger.info(f'{current_user.name} has logged out')
    logout_user()
    return redirect(url_for("home"))

@app.route('/about')
def aboutus():
    app.logger.info("Guest has arrived about us")
    return render_template("aboutus.html")

if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc")