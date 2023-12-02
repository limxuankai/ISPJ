from flask import Flask, flash, render_template, request, redirect, session, abort
import requests
import datetime
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import os 
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)

app.config["SECRET_KEY"] = "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"
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=1)
app.config['SESSION_COOKIE_SECURE'] = True
GOOGLE_CLIENT_ID = "326380353762-pek05h1clqj4likpcjtqba5gdf831okv.apps.googleusercontent.com"
flow = Flow.from_client_secrets_file(
    client_secrets_file="./static/secrets/client_secret.json",
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost/callback"
)

def forced_login(function):
    def wrapper(*args, **kwargs):
        if 'google_id' not in session:
            return abort(401)
        else:
            return function
    return wrapper

@app.route('/',methods=['GET','POST'])
@app.route('/home',methods=['GET','POST'])
def home():
    return render_template('home.html')

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route('/callback', methods=['GET','POST'])
def callback():
    flow.fetch_token(authorization_response=request.url)
    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/dashboard")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route('/dashboard', methods=['GET','POST'])
@forced_login
def dashboard():
    return render_template("dashboard.html")



if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0",port=80)