import os

from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = open(os.path.join(os.path.dirname(__file__), 'secret_key.txt')).read()

from app import routes
