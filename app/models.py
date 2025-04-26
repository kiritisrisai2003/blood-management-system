# app/models.py
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager
from flask_login import UserMixin
from app import app , mail ,db
from flask_mail import Message

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    blood_group = db.Column(db.String(3))
    phone_number = db.Column(db.String(15))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'
    
    
    

    
    



       
    
    
    

    



    
   
    
