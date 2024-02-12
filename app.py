import os
import json
import sqlite3
import datetime
import boto3
import docx2txt
import pandas as pd
import nltk
import uuid
import boto3
import jwt
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score
from datetime import datetime, timedelta
from flask import Flask, redirect, request, url_for,render_template,abort,flash, jsonify
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
import classification
from filedetailidk import *
from userdetailidk import *
from user import User, sql_query
import logging
from logging.handlers import RotatingFileHandler
import mysql.connector
from test import generatekey, Evaluate_Key
from encryption import encrypt, decrypt
import io

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests

UPLOAD_FACE_FOLDER = 'faceuploads'

JWTSECRET_KEY = 'Ispjsofun'

IPAddr = "104.196.231.172"

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
    accessliste = []
    useraccessliste = []
    User_Role = sql_query(f"SELECT ROLE FROM user WHERE ID={current_user.id}")
    app.logger.info(f'{current_user.name} has arrived at dashboard')
    if User_Role[0][0] != 'Admin':
        Access_Level = sql_query(f"SELECT Level FROM user WHERE Email = '{current_user.email}'")
        Files = sql_query(f"SELECT ID, Name, Status, Access_Level FROM document WHERE Access_Level <= {Access_Level[0][0]}")
        List_Files = [docdetail(row[0],row[1],row[2],row[3]) for row in Files]
        return render_template("dashboard.html", fileliste = List_Files)
    else:
        Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
        Cursor = Connection_Database.cursor()
        query = f"SELECT ID, Name, Status, Access_Level FROM document WHERE Status <> 'Classified' "
        Cursor.execute(query)
        changeaccess = Cursor.fetchall()
        for row in changeaccess:
            accessliste.append(docdetail(row[0], row[1], row[2], row[3]))
        Cursor.close()
        Cursor = Connection_Database.cursor()
        Connection_Database.close()

        Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
        Cursor = Connection_Database.cursor()
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
    
@app.route('/presigned', methods=['GET','POST'])
def presigned():
    # AWS credentials and S3 bucket information
    aws_access_key_id = 'AKIA2LOZ4RPA6DWSOH3Q'
    aws_secret_access_key = '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'
    region_name = 'ap-southeast-2'
    bucket_name = 'documents-for-ispj'

    success = request.args.get('success', False)

    
    filename = request.args.get('filename')   
    Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
    Cursor = Connection_Database.cursor()
    query = f"SELECT Access_Level FROM document WHERE Name = '{filename}' "
    Cursor.execute(query)
    FileLevel = Cursor.fetchone()
    Cursor.close()
    Connection_Database.close()

    if not success and FileLevel[0] == 3:
        success = request.args.get('success', False)
        if not success:
            token = jwt.encode({'filename': filename}, JWTSECRET_KEY, algorithm='HS256')
            return redirect(url_for('faceauth', token=token))
   
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

@app.route('/files')
@login_required
def files():
        fileliste = []
        try:
            Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
            Cursor = Connection_Database.cursor()
            query = f"SELECT Level FROM user WHERE Email = '{current_user.email}'"
            Cursor.execute(query)
            UserLevel = Cursor.fetchone()
            UserLevel = UserLevel[0]
            print(UserLevel)
            query = f"SELECT ID, Name, Status, Access_Level FROM document WHERE Access_Level <= {UserLevel}"
            # query = f"SELECT FileID, FileName, Status, AccessLevel FROM documents WHERE AccessLevel <= 3"
            Cursor.execute(query)
            filedetailss = Cursor.fetchall()
            print("got filedetails")
            for row in filedetailss:
                fileliste.append(docdetail(row[0], row[1], row[2], row[3]))
                print("in for loop")
            Cursor.close()
            Connection_Database.close()
        except Exception as e:
            print (f"Error: {e}")
        return render_template("files.html", fileliste=fileliste)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    aws_access_key_id = 'AKIA2LOZ4RPA6DWSOH3Q'
    aws_secret_access_key = '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'
    region_name = 'ap-southeast-2'
    bucket_name = 'documents-for-ispj'

    uploaded_file = request.files['file']
    server_key, server_table, client_key, client_table = generatekey()
    KEY = Evaluate_Key(server_key, server_table, client_key, client_table)
    encryted_file = uploaded_file.read()
    encryted_file = encrypt(encryted_file, KEY)
    encrypted_file = io.BytesIO(encryted_file)
    server_table = (','.join(server_table))

    result = 'success'  # Default to success

    if uploaded_file.filename != '':
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

                print({current_user.id})
                Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
                Cursor = Connection_Database.cursor()
                query = f"INSERT INTO document (ID, Name, Status, Access_Level,User_ID, QUBITS, LIST) VALUES ('{uuid.uuid4()}','{uploaded_file.filename}','BeforeML',1,'{current_user.id}', '{server_key}', '{server_table}')"
                Cursor.execute(query)
                Connection_Database.commit()
                Cursor.close()
                Connection_Database.close()
                print("successfully updated")
            except Exception as e:
                print(f'Failed to upload or update db: {e}')
                result = 'fail'

    return jsonify(result)




# @app.route('/upload', methods=['POST'])
# def upload():
#     # AWS credentials and S3 bucket information
#     aws_access_key_id = 'AKIA2LOZ4RPA6DWSOH3Q'
#     aws_secret_access_key = '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'
#     region_name = 'ap-southeast-2'
#     bucket_name = 'documents-for-ispj'

#     # Get the uploaded file from the form
#     uploaded_file = request.files['image']

#     # Check if a file is selected
#     if uploaded_file.filename != '':
#         # Create an S3 client
#         s3 = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=region_name)

#         # Upload the file to S3
#         s3.upload_fileobj(uploaded_file, bucket_name, uploaded_file.filename)

#         # Make the uploaded object public
#         s3.copy_object(
#             Bucket=bucket_name,
#             CopySource={'Bucket': bucket_name, 'Key': uploaded_file.filename},
#             Key=uploaded_file.filename,
#             MetadataDirective='REPLACE',
#             ContentType='image/jpg',
#             Metadata={'Content-Disposition': 'inline'}
#         )
#         s3.put_object_acl(ACL='public-read', Bucket=bucket_name, Key=uploaded_file.filename)

#         # Get the public URL of the object
#         object_url = f"https://{bucket_name}.s3.{region_name}.amazonaws.com/{uploaded_file.filename}"

#         print(f"The public URL of the image for preview is: {object_url}")

#         return f"File successfully uploaded. Public URL: {object_url}"

#     return "No file selected."


@app.route('/success', methods=['POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
        f.save(file_path)
        app.logger.info(f'{current_user.name} uploaded {f.filename}')
        server_key, client_table, client_key, server_table = generatekey()
        with open('client_side.txt', "w") as client_file:
            client_file.write(client_key + '\n')
            client_file.write(','.join(client_table))
        with open('server_side.txt', "w") as server_file:
            server_file.write(server_key + '\n')
            server_file.write(','.join(server_table))
    return render_template('success.html', file_path= file_path, filename = f.filename)

@app.route('/encryption')
@login_required
def encryption():
    with open('client_side.txt', 'r') as client_file:
        lines = client_file.readlines()
        client_key = lines[0]
        client_table = lines[1]
    with open('server_side.txt', 'r') as server_file:
        lines = server_file.readlines()
        server_key = lines[0]
        server_table = lines[1]
    formatted_client_list = [item.strip(',') for item in list(client_table) if item.strip(',') != '']
    formatted_server_list = [item.strip(',') for item in list(server_table) if item.strip(',') != '']
    KEY = Evaluate_Key(server_key, formatted_server_list, client_key, formatted_client_list)
    with open('static/files/20240205_190306.jpg', 'rb') as plain:
        Encrypted = encrypt(plain.read(), KEY)
    file_path = app.config['UPLOAD_FOLDER']
    with open('static/files/encrypted.jpg', 'wb') as e:
        e.write(Encrypted)

    return render_template('encryption.html', Encrypted_File = 'static/files/encrypted.jpg')

@app.route('/decryption')
@login_required
def decryption():
    with open('client_side.txt', 'r') as client_file:
        lines = client_file.readlines()
        client_key = lines[0]
        client_table = lines[1]
    with open('server_side.txt', 'r') as server_file:
        lines = server_file.readlines()
        server_key = lines[0]
        server_table = lines[1]
    formatted_client_list = [item.strip(',') for item in list(client_table) if item.strip(',') != '']
    formatted_server_list = [item.strip(',') for item in list(server_table) if item.strip(',') != '']
    KEY = Evaluate_Key(server_key, formatted_server_list, client_key, formatted_client_list)
    with open('static/files/encrypted.jpg', 'rb') as cipher:
        Decrypted = decrypt(cipher.read(), KEY)
    file_path = app.config['UPLOAD_FOLDER']
    with open('static/files/decrypted.jpg', 'wb') as e:
        e.write(Decrypted)

    return render_template('decryption.html', Decrypted_File = 'static/files/decrypted.jpg')
if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc")
