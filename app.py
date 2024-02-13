import os
import json
import shutil
import datetime
import boto3
import docx2txt
import pandas as pd
import nltk
import uuid
import boto3
import jwt
import bcrypt
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score
from datetime import datetime, timedelta
from flask import Flask, redirect, request, url_for,render_template,abort,flash, jsonify, send_file
from flask_cors import CORS
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests
import base64
import threading
import classification
from filedetailidk import *
from filedetailidk2 import *
from userdetailidk import *
from user import User, sql_query
import logging
from logging.handlers import RotatingFileHandler
import mysql.connector
from test import generatekey, Evaluate_Key
from encryption import encrypt, decrypt
import io
import tempfile
import magic
import time
import random

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests

UPLOAD_FACE_FOLDER = 'faceuploads'

JWTSECRET_KEY = 'Ispjsofun'

IPAddr = "104.196.231.172"

scheduled_deletions = {}
expiration_time_token = datetime.utcnow() + timedelta(hours=1)

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
app.config['UPLOAD_FOLDER'] = 'static/files/'

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
     id = unique_id, name=users_name, email=users_email, profile_pic=picture
)
    if User.get(unique_id) is None:
        User.create(unique_id,users_name,picture, users_email)
    login_user(user)
    return redirect(url_for("dashboard"))

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    check_and_delete("static/files/")
    accessliste = []
    useraccessliste = []
    List_Files = []
    User_Role = sql_query(f"SELECT ROLE FROM user WHERE ID={current_user.id}")
    app.logger.info(f'{current_user.name} has arrived at dashboard')
    if User_Role[0][0] != 'Admin':
        Access_Level = sql_query(f"SELECT Level FROM user WHERE Email = '{current_user.email}'")
        Files = sql_query(f"SELECT ID, Name, Status, Access_Level, User_ID FROM document WHERE Access_Level <= {Access_Level[0][0]}")
        for row in Files:
            filename = row[1]
            token = jwt.encode({'filename': filename}, JWTSECRET_KEY, algorithm='HS256')
            List_Files.append(docdetail(row[0],row[1],row[2],row[3], row[4],token))
        return render_template("dashboard.html", fileliste = List_Files, user=current_user)
    else:
        Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
        Cursor = Connection_Database.cursor()
        query = f"SELECT ID, Name, Status, Access_Level, User_ID FROM document WHERE Status <> 'Classified' "
        Cursor.execute(query)
        changeaccess = Cursor.fetchall()
        for row in changeaccess:
            filename = row[1]
            token = jwt.encode({'filename': filename}, JWTSECRET_KEY, algorithm='HS256')
            accessliste.append(docdetail(row[0], row[1], row[2], row[3],row[4],token))
        
        
        
        query_2 = "SELECT Email, ROLE, Level, ID FROM user WHERE ROLE = 'User'"
        Cursor.execute(query_2)
        result_set_2 = Cursor.fetchall()
        for row in result_set_2:
            useraccessliste.append(userdetail(row[0], row[1], row[2], row[3]))
        Cursor.close()
        Connection_Database.close()
        return render_template("admin.html", accessliste = accessliste, useraccessliste = useraccessliste)

@app.route('/info')
@login_required
def info():
    app.logger.info(f'{current_user.name} is viewing account info')
    return render_template("info.html", info={"Name":current_user.name, "Email":current_user.email}, pic=current_user.profile_pic)


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

@app.route('/faceauth')
@login_required
def faceauth():
    app.logger.info("user doing face authentication")
    token = request.args.get('token')
    decoded_token = jwt.decode(token, JWTSECRET_KEY, algorithms=['HS256'])
    filename = decoded_token.get('filename')
    print(f"at faceauth {filename}")
    return render_template("faceauth.html", filename=filename)

def save_image(data_uri):
    _, encoded = data_uri.split(",", 1)
    img_data = base64.b64decode(encoded)
    image_name = str(uuid.uuid4()) + ".jpg"
    image_path = os.path.join(UPLOAD_FACE_FOLDER, image_name)
    with open(image_path, "wb") as f:
        f.write(img_data)
    return image_name

@app.route("/uploadface", methods=["POST"])
def upload_image():
    if "image" not in request.form:
        return jsonify({"error": "No image data found"}), 400
    image_name = save_image(request.form["image"])
    return jsonify({"success": True, "image_name": image_name})

@app.route("/authenticate", methods=["POST"])
def authenticate():
    filename = request.args.get('filename')
    if "image" not in request.form:
        return jsonify({"error": "No image data found"}), 400
    image_name = save_image(request.form["image"])
    try:
        response = requests.put(
            "https://rd376l6qic.execute-api.ap-southeast-2.amazonaws.com/dev/ispj-is-extremely-fun-visitor/{}.jpeg".format(image_name),
            headers={"Content-Type": "image/jpeg"},
            data=base64.b64decode(request.form["image"].split(",")[1]),
        )
        print("PUT response content:", response.content)
        if response.status_code == 200:
            auth_response = requests.get(
                "https://rd376l6qic.execute-api.ap-southeast-2.amazonaws.com/dev/employee",
                params={"objectKey": "{}.jpeg".format(image_name)}
            )
            print("GET response content:", auth_response.content)
            auth_data = auth_response.json()
            if auth_data.get("Message") == "Success":
                # return jsonify({"success": True, "user": auth_data})
                aws_access_key_id = 'AKIA2LOZ4RPA6DWSOH3Q'
                aws_secret_access_key = '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'
                region_name = 'ap-southeast-2'
                bucket_name = 'documents-for-ispj'
                s3 = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=region_name)
                preview_presigned_url = generate_presigned_url(s3, bucket_name, filename, expiration_time=180, content_disposition='inline')
                print(f"level 3{preview_presigned_url}")
                return jsonify({"success": True, "user": preview_presigned_url})

            else:
                return jsonify({"success": False, "error": "Authentication failed"}), 401
        else:
            return jsonify({"success": False, "error": "Error during image upload"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/verify', methods=['GET','POST'])
@login_required
def verify():
    if request.method == 'POST':
        entered_password = request.form.get('password')
        token = request.args.get('token')
        decoded_token = jwt.decode(token, JWTSECRET_KEY, algorithms=['HS256'])
        filename = decoded_token.get('filename')
        Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
        Cursor = Connection_Database.cursor()
        query = f"SELECT Password FROM document WHERE Name = '{filename}' "
        Cursor.execute(query)
        hashed_password = Cursor.fetchone()
        hashed_password = hashed_password[0]
        hashed_password = hashed_password.encode('utf8')
        if check_password(entered_password, hashed_password):
            token = jwt.encode({'filename': filename, 'success': True, 'exp': expiration_time_token}, JWTSECRET_KEY, algorithm='HS256')
            return redirect(url_for('presigned',token=token))
        else:
            print("password is incorrect")
            # Password is incorrect, you may want to show an error message
            return render_template('verify.html', error='Incorrect password')

    # If it's a GET request or incorrect password, render the verification page
    return render_template('verify.html', error=None)

def check_password(plain_password, hashed_password):
    # Check if a plain password matches a hashed password
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

@app.route('/presigned', methods=['GET','POST'])
@login_required
def presigned():
    # AWS credentials and S3 bucket information
    aws_access_key_id = 'AKIA2LOZ4RPA6DWSOH3Q'
    aws_secret_access_key = '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'
    region_name = 'ap-southeast-2'
    bucket_name = 'documents-for-ispj'
    success = False
    token = request.args.get('token')

    decoded_token = jwt.decode(token, JWTSECRET_KEY, algorithms=['HS256'])
    filename = decoded_token.get('filename')
    success = decoded_token.get('success',False)

    Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
    Cursor = Connection_Database.cursor()
    query = f"SELECT Access_Level FROM document WHERE Name = '{filename}' "
    Cursor.execute(query)
    FileLevel = Cursor.fetchone()

    Cursor.close()
    if FileLevel[0] == 3 and success:
        token = jwt.encode({'filename': filename, 'exp': expiration_time_token}, JWTSECRET_KEY, algorithm='HS256')
        return redirect(url_for('faceauth', token=token))

    if success:
        Cursor = Connection_Database.cursor()
        query = f"SELECT Level, Role FROM user WHERE Email = '{current_user.email}' "
        Cursor.execute(query)
        userinfo = Cursor.fetchone()
        Level = userinfo[0]
        print(Level)
        Role = userinfo[1]
        print(Role)
        print(FileLevel)
        Cursor.close()
        Connection_Database.close()
        if Level >= FileLevel[0] or Role == "Admin":
            s3 = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=region_name)
            preview_presigned_url = generate_presigned_url(s3, bucket_name, filename, expiration_time=180, content_disposition='inline')
            print(f"level 1{preview_presigned_url}")
            return redirect(preview_presigned_url, code=302)


    if FileLevel[0] == 2 or FileLevel[0] ==3:
        token = jwt.encode({'filename': filename, 'exp': expiration_time_token}, JWTSECRET_KEY, algorithm='HS256')
        return redirect(url_for("verify", token=token))

    Cursor = Connection_Database.cursor()
    query = f"SELECT Level, Role FROM user WHERE Email = '{current_user.email}' "
    Cursor.execute(query)
    userinfo = Cursor.fetchone()
    Level = userinfo[0]
    print(Level)
    Role = userinfo[1]
    print(Role)
    print(FileLevel)
    Cursor.close()
    Connection_Database.close()
    if Level >= FileLevel[0] or Role == "Admin":
        s3 = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=region_name)
        preview_presigned_url = generate_presigned_url(s3, bucket_name, filename, expiration_time=180, content_disposition='inline')
        print(f"level 1{preview_presigned_url}")
        return redirect(preview_presigned_url, code=302)

def generate_presigned_url(s3_client, bucket, key, expiration_time, content_disposition='inline'):
    #Generate a pre-signed URL for the S3 object with a specific expiration time
    url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket, 'Key': key, 'ResponseContentDisposition': content_disposition},
        ExpiresIn=expiration_time,

    )
    return url

@app.route('/update_fileaccess', methods=['POST'])
def update_fileaccess():
    try:
        fileid = request.form['fileid']
        print(fileid)
        selected_accesslevel = request.form['fileaccess']
        print(selected_accesslevel)
        Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
        Cursor = Connection_Database.cursor()
        update_query = f"UPDATE document SET Access_Level = '{selected_accesslevel}', Status= 'Classified' WHERE ID = '{fileid}'"
        Cursor.execute(update_query)
        Connection_Database.commit()
        Cursor.close()
        Connection_Database.close()
        print('successfully changed file access level')
        # Your existing code to update the database based on fileid and selected_accesslevel

        # Assuming you want to return some response data (e.g., JSON)

        return jsonify({"success": str("success")})
    except Exception as e:
        print(e)
        return jsonify({"error": "failed"})

@app.route('/update_useraccess', methods=['POST'])
def update_useraccess():
    try:
        userid = request.form['userid']
        print(f"userid={userid}")
        selected_userlevel = request.form['useraccess']
        print(f"selected user level={selected_userlevel}")
        Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
        Cursor = Connection_Database.cursor()
        update_query = f"UPDATE user SET Level = '{selected_userlevel}' WHERE ID = '{userid}'"
        Cursor.execute(update_query)
        Connection_Database.commit()
        Cursor.close()
        Connection_Database.close()
        # Your existing code to update the database based on fileid and selected_accesslevel

        # Assuming you want to return some response data (e.g., JSON)

        return jsonify({"success": str("success")})
    except Exception as e:
        print(e)
        return jsonify({"error": "failed"})

@app.route('/delete_file', methods=['POST'])
def delete_file():
    aws_access_key_id = 'AKIA2LOZ4RPA6DWSOH3Q'
    aws_secret_access_key = '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'
    region_name = 'ap-southeast-2'
    bucket_name = 'documents-for-ispj'
    filename = request.form.get('filename')
    s3 = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=region_name)
    s3.delete_object(Bucket=bucket_name, Key=filename)

    Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
    Cursor = Connection_Database.cursor()
    query1 = f"SELECT ID FROM user WHERE Email = '{current_user.email}'"
    Cursor.execute(query1)
    UserLevel = Cursor.fetchone()
    userid = UserLevel[0]
    query2 = f"SELECT User_ID FROM document WHERE Name = '{filename}'"
    Cursor.execute(query2)
    fileuserid = Cursor.fetchone()
    fileuserid = fileuserid[0]
    if fileuserid == userid or userid == "105552234048794201768":
        query3 = f"DELETE FROM document WHERE Name = '{filename}';"
        print("if user eq user")
        Cursor.execute(query3)
        Connection_Database.commit()
        Cursor.close()
        Connection_Database.close()
        app.logger.info("user deleted file")
        flash('file deleted')
        return redirect(url_for("files"))
    else:
        flash('You are not authorised!')
        return redirect(url_for('files'))


@app.route('/files')
@login_required
def files():
        fileliste = []
        try:
            Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
            Cursor = Connection_Database.cursor()
            query = f"SELECT ID, Level FROM user WHERE Email = '{current_user.email}'"
            Cursor.execute(query)
            UserLevel = Cursor.fetchone()
            userid = UserLevel[0]
            userlevel = UserLevel[1]

            print(f"Userid {userid}")
            query = f"SELECT ID, Name, Status, Access_Level, User_ID FROM document WHERE Access_Level <= {userlevel}"
            # query = f"SELECT FileID, FileName, Status, AccessLevel FROM documents WHERE AccessLevel <= 3"
            Cursor.execute(query)
            filedetailss = Cursor.fetchall()
            print("got filedetails")

            for row in filedetailss:
                filename = row[1]
                token = jwt.encode({'filename': filename}, JWTSECRET_KEY, algorithm='HS256')
                fileliste.append(docdetail2(row[0], row[1], row[2], row[3], row[4],token))
                print("in for loop")
            Cursor.close()
            Connection_Database.close()
        except Exception as e:
            print (f"Error: {e}")
        return render_template("files.html", fileliste=fileliste, user=current_user, userid=userid)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    aws_access_key_id = 'AKIA2LOZ4RPA6DWSOH3Q'
    aws_secret_access_key = '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'
    region_name = 'ap-southeast-2'
    bucket_name = 'documents-for-ispj'

    uploaded_file = request.files['file']
    expiration_time = request.form['auto']
    docpassword = request.form['password']
    hashed_password = bcrypt.hashpw(docpassword.encode('utf-8'), bcrypt.gensalt())
    print(f'expiration_time: {expiration_time}')
    print(f'hashed_password: {hashed_password}')
    server_key, server_table, client_key, client_table = generatekey()
    KEY = Evaluate_Key(server_key, server_table, client_key, client_table)
    encryted_file = uploaded_file.read()
    encryted_file = encrypt(encryted_file, KEY)
    encrypted_file = io.BytesIO(encryted_file)
    server_table = (','.join(server_table))
    client_table = (','.join(client_table))
    result = 'fail'  # Default to success

    if uploaded_file.filename != '':
        if expiration_time != '':
            expiration_time = float(request.form['auto'])
            schedule_deletion(uploaded_file.filename, expiration_time)
        Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
        Cursor = Connection_Database.cursor()
        query = f"SELECT * FROM document WHERE Name = '{uploaded_file.filename}'"
        Cursor.execute(query)
        result = 'duplicate' if Cursor.fetchone() else 'success'
        Cursor.close()
        Connection_Database.close()

        if result == 'success':
            try:
                print('still testing')
                s3 = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=region_name)
                s3.upload_fileobj(encrypted_file, bucket_name, uploaded_file.filename)
                random_level = random.randint(1, 3)
                print({current_user.id})
                Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
                Cursor = Connection_Database.cursor()
                query = f"INSERT INTO document (ID, Name, Status, Access_Level,User_ID, QUBITS, LIST, Password) VALUES ('{uuid.uuid4()}','{uploaded_file.filename}','AfterML',{random_level},'{current_user.id}', '{server_key}', '{server_table}', '{hashed_password.decode('utf-8')}')"
                Cursor.execute(query)
                Connection_Database.commit()
                Cursor.close()
                Connection_Database.close()
                print("successfully updated")
            except Exception as e:
                print(f'Failed to upload or update db: {e}')
                result = 'fail'
    print(result)
    return jsonify(result)

def schedule_deletion(filename, expiration_hours):
    # Calculate the deletion time based on the current time plus the specified hours
    expiration_datetime = datetime.utcnow() + timedelta(hours=expiration_hours)
    print(f"expiration_datetime {expiration_datetime}")
    # Calculate the delay until deletion
    delay_seconds = (expiration_datetime - datetime.utcnow()).total_seconds()
    print(f"delay_seconds {delay_seconds}")
    # Schedule the deletion in a background thread
    deletion_thread = threading.Thread(target=delayed_deletion, args=(filename,), kwargs={'delay_seconds': delay_seconds})
    deletion_thread.start()

    # Store the scheduled deletion time
    scheduled_deletions[filename] = expiration_datetime

def delayed_deletion(filename, delay_seconds):
    # Wait for the specified delay
    time.sleep(delay_seconds)
    try:
        aws_access_key_id = 'AKIA2LOZ4RPA6DWSOH3Q'
        aws_secret_access_key = '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'
        region_name = 'ap-southeast-2'
        bucket_name = 'documents-for-ispj'
        s3 = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=region_name)
        s3.delete_object(Bucket=bucket_name, Key=filename)
        Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
        Cursor = Connection_Database.cursor()
        query3 = f"DELETE FROM document WHERE Name = '{filename}';"
        Cursor.execute(query3)
        Connection_Database.commit()
        Cursor.close()
        Connection_Database.close()
        print("auto deleted")
    except Exception as e:
        print(e)










@app.route('/decryption')
@login_required
def decryption():
    return render_template('decryption.html', user=current_user)


@app.route('/download-file/<client_key>/<client_table>')
def download_file(client_key, client_table):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(client_key.encode() + b'\n')
            temp_file.write(','.join(client_table).encode())
            temp_file_path = temp_file.name

            temp_file.close()

            return send_file(temp_file_path, as_attachment=True, download_name='encrypted.txt')
    except Exception as e:
        return str(e), 404

@app.route('/decrypt', methods=['POST'])
@login_required
def decrypts():
    uploaded_file = [request.files['file'], request.files['key']]
    lines = uploaded_file[1].readlines()
    client_key = lines[0]
    client_table = lines[1]
    client_key = client_key.decode()
    client_table = client_table.decode()
    server_key, server_table = sql_query(f"SELECT QUBITS, LIST FROM document WHERE Name= '{uploaded_file[0].filename}'")[0]
    formatted_server_list = [item.strip(',') for item in list(server_table) if item.strip(',') != '']
    formatted_client_list = [item.strip(',') for item in list(client_table) if item.strip(',') != '']
    formatted_client_list = ''.join(formatted_client_list)
    KEY = Evaluate_Key(server_key, formatted_server_list, client_key, formatted_client_list)
    PT = decrypt(uploaded_file[0].read(), KEY)
    file_extension = get_file_extension(PT)
    file_path = 'static/files/decrypt' + file_extension
    file_name = 'decrypt' + file_extension
    with open(file_path, 'wb') as e:
        e.write(PT)
    return render_template('decryption.html', file_name = file_name, user=current_user, CT = PT)

def get_file_extension(file_content):
    # Initialize magic
    magic_instance = magic.Magic(mime=True)

    # Get the MIME type of the file
    mime_type = magic_instance.from_buffer(file_content)

    # Get the file extension based on the MIME type
    mime_to_ext = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/gif': '.gif',
    'image/bmp': '.bmp',
    'image/tiff': '.tiff',
    'image/webp': '.webp',
    'application/pdf': '.pdf',
    'text/plain': '.txt',
    'application/json': '.json',
    'application/xml': '.xml',
    'application/zip': '.zip',
    'application/x-tar': '.tar',
    'application/x-gzip': '.gz',
    'application/x-bzip2': '.bz2',
    'application/x-rar-compressed': '.rar',
    'video/mp4': '.mp4',
    'video/mpeg': '.mpeg',
    'audio/mpeg': '.mp3',
    'audio/wav': '.wav',
    'audio/ogg': '.ogg',
    'application/vnd.ms-excel': '.xls',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
    'application/msword': '.doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
   }
    # If the MIME type is not recognized, use a default extension
    default_extension = '.txt'
    file_extension = mime_to_ext.get(mime_type, default_extension)

    return file_extension

@app.route('/download/<file_name>')
def download(file_name):
    file_path = 'static/files/' + file_name
    return send_file(
        file_path,
        as_attachment=True,
        download_name='temp_file.png'
        )

def check_and_delete(directory):
    items = os.listdir(directory)
    for item in items:
        item_path = os.path.join(directory, item)
        if os.path.isfile(item_path):
                os.remove(item_path)
        elif os.path.isdir(item_path):
                check_and_delete(item_path)
    return

if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc")
