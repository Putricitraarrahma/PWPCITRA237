# config/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Membuat instance aplikasi Flask
app = Flask(__name__)


from .models import db
from .config import Config
