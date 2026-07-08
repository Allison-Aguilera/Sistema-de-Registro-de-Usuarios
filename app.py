import oracledb
import os
from flask import Flask
from dotenv import load_dotenv
from routes.auth import auth

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET")

def get_connection():
    return oracledb.connect(
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        dsn=os.getenv("DB_DSN")
    )

app.get_connection = get_connection

print("Conectado exitosamente a Oracle")

app.register_blueprint(auth)

if __name__ == "__main__":
    app.run(debug=True)