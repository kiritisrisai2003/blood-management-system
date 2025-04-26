# run.py
from app import app, db
from app.models import User
from email.message import EmailMessage

db.create_all()

        # Create the admin account (only if it doesn't exist)






def create_admin():
    """
    Create an admin account if it doesn't already exist.
    """
    with app.app_context():  # Ensure this runs within the app context
        # Check if an admin account already exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            # Create the admin account
            admin = User(
                username='admin',
                email='admin@example.com',
                blood_group='O+',
                phone_number='0000000000'
            )
            admin.set_password('adminpassword')  # Hash the password
            db.session.add(admin)
            db.session.commit()
            print("Admin account created successfully!")
        else:
            print("Admin account already exists. Skipping creation.")

with app.app_context():
        # Create database tables if they don't exist
        db.create_all()

        # Create the admin account (only if it doesn't exist)
        create_admin()


if __name__ == '__main__':
    with app.app_context():
        # Create database tables if they don't exist
        db.create_all()

        # Create the admin account (only if it doesn't exist)
        create_admin()
    

    # Run the Flask application
    app.run(debug=True)
   