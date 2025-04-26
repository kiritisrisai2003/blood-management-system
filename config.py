import os
#from app import app





class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'kiritisrisai5019@gmail.com'
    MAIL_PASSWORD = 'rxjb njiu nfry rwje'

   

    '''MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = os.getenv('EMAIL_USER')  # Set this in your environment
    MAIL_PASSWORD = os.getenv('EMAIL_PASS')  # Set this in your environment
    MAIL_DEFAULT_SENDER = os.getenv('EMAIL_USER') # Use same email as MAIL_USERNAME'''

'''app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = "kiritisrisai5019@gmail.com"
app.config["MAIL_PASSWORD"] = "rxjbnjiunfryrwje"'''
   




EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')

