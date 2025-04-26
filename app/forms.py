# app/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_wtf.recaptcha import RecaptchaField
from flask_mail import Message

from app import app ,db ,mail


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    blood_group = SelectField('Blood Group', choices=[('A+', 'A+'), ('A-', 'A-'), ('B+', 'B+'), ('B-', 'B-'), ('O+', 'O+'), ('O-', 'O-'), ('AB+', 'AB+'), ('AB-', 'AB-')], validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')  # Add this field
    submit = SubmitField('Login')

'''class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    recaptcha = RecaptchaField()  # CAPTCHA field
    submit = SubmitField('Send OTP')

class ResetPasswordForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')'''
class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send OTP')

class OTPForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[DataRequired()])
    submit = SubmitField('Verify OTP')

class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired()])

    submit = SubmitField('Reset Password')



    






    