import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_uploads import UploadSet, configure_uploads, IMAGES

from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage
db = SQLAlchemy()
# create the app
app = Flask(__name__)
# configure the SQLite database, relative to the app instance folder
# app.config['UPLOADED_IMAGES_DEST'] = os.path.join(app.root_path, 'uploads', 'images')
# images = UploadSet('images', IMAGES)
# configure_uploads(app, images)
# db.init_app(app)
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    description = db.Column(db.String(255))
    price = db.Column(db.Integer())
    brand = db.Column(db.String(90))

    def __init__(self,name,description,price,brand):
        self.name = name
        self.description = description
        self.price = price
        self.brand = brand

    def json(self):
        return{'name':self.name, 'description':self.description, 'price':self.price, 'brand':self.brand} 

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(255),unique=True)
    name = db.Column(db.String(255))
    password = db.Column(db.String(19))
    admin = db.Column(db.Boolean)

# class Todo(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     text = db.Column(db.String(255))
#     complete = db.column(db.Boolean)
#     user_id = db.Column(db.Integer)
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    email = db.Column(db.String(255), nullable=False, unique=True)
    subject = db.Column(db.String(255))
    # message = db.Column(db.String(255),nullable=True)


    def __init__(self,name,email,subject):
        self.name = name
        self.email = email
        self.subject = subject


    def json(self):
        return {'name': self.name, 'email': self.email, 'subject': self.subject}



class AboutUs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    description = db.Column(db.String(255))
    # image = db.Column(db.String(255))

    def __init__(self, title, description, ):
        self.title = title
        self.description = description


    def json(self):
        return {'title': self.title, 'discription':self.discription}









    