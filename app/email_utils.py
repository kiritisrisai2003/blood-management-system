
from flask import Flask, request, render_template, flash, redirect, url_for
from email.message import EmailMessage
import smtplib
from flask_mail import Message
from app import app ,mail
from email.mime.text import MIMEText


def send_email(to_email, blood_group):
    sender_email = "kiritisrisai5019@gmail.com"  # Replace with your email
    sender_password = "rxjb njiu nfry rwje"  # Use app password if using Gmail
    
    subject = "Urgent: Blood Donation Request"
    body = f"A blood donation request has been made for blood group {blood_group}. If you are available to donate, please contact the requester."
    
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Error sending email: {e}")





    
