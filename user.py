from flask_login import UserMixin
import mysql.connector

IPAddr = "104.196.231.172"

def sql_query(query):
    try:
        Connection_Database = mysql.connector.connect(host=IPAddr, user="root", database="ispj", password="")
        Cursor = Connection_Database.cursor()
        Cursor.execute(query)
        if 'SELECT' in query:
            Data = Cursor.fetchmany()
        else:
            Data = None
        Connection_Database.commit()
        Connection_Database.close()
        Cursor.close()
        return Data
    except Exception as e:
            print (f"Error: {e}")

class User(UserMixin):
    def __init__(self, id, name, email, profile_pic):
        self.id = id
        self.name = name
        self.email = email
        self.profile_pic = profile_pic


    @staticmethod
    def get(user_id):
        user = sql_query(f"SELECT * FROM user WHERE ID='{user_id}'")
        if not user:
            return None
        user = User(
            id=user[0][0], name=user[0][3], email=user[0][-1], profile_pic=user[0][-2]
        )
        return user

    @staticmethod
    def create(ID, name, profile_pic, email):
        try:
            sql_query(f"INSERT INTO user(ID, Role, Level, Name, Pfp, Email) VALUES ('{ID}','User', 1, '{name}', '{profile_pic}', '{email}')")
        except Exception as e:
            print(e)
