from flask import render_template, redirect, url_for, flash, request ,session
from flask_login import login_user, logout_user, current_user, login_required
from app import app, db, mail
from werkzeug.security import generate_password_hash, check_password_hash
from app.forms import ForgotPasswordForm, OTPForm,ResetPasswordForm, RegistrationForm, LoginForm
from app.models import User
from flask_mail import Message
from app.email_utils import send_email

import random
import requests


# Store OTPs temporarily (in production, use a database or Redis)
#otp_storage = {}

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            blood_group=form.blood_group.data,
            phone_number=form.phone_number.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered donor!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password. <a href="{}">Forgot Password?</a>'.format(url_for('forgot_password')), 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('donors'))
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/donors')
@login_required
def donors():
    blood_group = current_user.blood_group
    donors_list = User.query.filter_by(blood_group=blood_group).all()
    return render_template('donors.html', title='Donors', donors_list=donors_list)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.username != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    donors_list = User.query.all()
    return render_template('admin.html', title='Admin', donors_list=donors_list)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_donor(id):
    if current_user.username != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index'))
    donor = User.query.get_or_404(id)
    db.session.delete(donor)
    db.session.commit()
    flash('Donor deleted successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/public_donors', methods=['GET', 'POST'])
def public_donors():
    # Fetch all unique blood groups from the database
    blood_groups = db.session.query(User.blood_group).distinct().all()
    blood_groups = [bg[0] for bg in blood_groups]  # Extract blood groups from the query result

    selected_blood_group = None
    donors_list = []

    if request.method == 'POST':
        # Get the selected blood group from the form
        selected_blood_group = request.form.get('blood_group')

        # Fetch donors with the selected blood group
        donors_list = User.query.filter_by(blood_group=selected_blood_group).all()

    return render_template('public_donors.html', title='Public Donors', blood_groups=blood_groups, selected_blood_group=selected_blood_group, donors_list=donors_list)
otp_storage = {}

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            otp_storage[email] = otp  # Store OTP

            # Send OTP via email
            msg = Message('Password Reset OTP', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Your OTP for password reset is: {otp}'
            mail.send(msg)

            flash('An OTP has been sent to your email.', 'info')
            session['email'] = email
            return redirect(url_for('verify_otp'))

        flash('Email not found!', 'danger')

    return render_template('forgot_password.html', form=form)
'''@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate and send OTP
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            otp_storage[email] = otp  # Store OTP temporarily

            # Send OTP via email
            msg = Message('Password Reset OTP', recipients=[email])
            msg.body = f'Your OTP for password reset is: {otp}'
            mail.send(msg)

            flash('An OTP has been sent to your email. Please check your inbox.', 'info')
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Email not found. Please enter a registered email address.', 'danger')

    return render_template('forgot_password.html', title='Forgot Password', form=form)'''


'''@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        otp = form.otp.data
        new_password = form.new_password.data

        # Verify OTP
        if email in otp_storage and otp_storage[email] == otp:
            user = User.query.filter_by(email=email).first()
            if user:
                user.set_password(new_password)
                db.session.commit()
                flash('Your password has been reset successfully. Please log in.', 'success')
                return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('reset_password.html', title='Reset Password', form=form, email=email)

print(f"MAIL_USERNAME: {app.config.get('MAIL_USERNAME')}")
print(f"MAIL_DEFAULT_SENDER: {app.config.get('MAIL_DEFAULT_SENDER')}")'''

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    form = OTPForm()
    email = session.get('email')

    if not email:
        return redirect(url_for('forgot_password'))

    if form.validate_on_submit():
        user_otp = form.otp.data

        if otp_storage.get(email) == user_otp:
            flash('OTP verified! Set your new password.', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid OTP. Try again!', 'danger')

    return render_template('verify_otp.html', form=form)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    email = session.get('email')

    if not email:
        return redirect(url_for('forgot_password'))

    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()

        if user:
            print(f"Updating password for: {user.email}")
            # Hash the new password before saving
            user.password = generate_password_hash(form.new_password.data)  # Store hashed password
            db.session.flush()
            db.session.commit()  # Commit the changes
            print("password is updated in database")

            flash('Password reset successful! You can now log in.', 'success')
            session.pop('email', None)  # Clear the session
            return redirect(url_for('login'))  # Redirect to login page
        else:
            flash('User not found. Please try again.', 'danger')

    return render_template('reset_password.html', form=form)
 


@app.route('/request_blood', methods=['GET', 'POST'])
def request_blood():
    if not current_user.is_authenticated:
        flash('Please log in to request blood.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        blood_group = request.form.get('blood_group')
        message = request.form.get('message')

        if not blood_group or not message:
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('request_blood'))

        # Fetch donors with the requested blood group
        donors = User.query.filter_by(blood_group=blood_group).all()

        if not donors:
            flash('No donors found for the selected blood group.', 'warning')
            return redirect(url_for('request_blood'))

        # Send email notifications to donors
        for donor in donors:
            send_email(donor.email, message)

        flash('Your request has been sent to donors.', 'success')
        return redirect(url_for('request_blood'))

    return render_template('request_blood.html', title='Request Blood')
