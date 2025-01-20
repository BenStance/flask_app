from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from datetime import timedelta
from datetime import datetime
import psutil
import json
from random import randint
from flask_mail import Mail, Message
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///TEYORADB.db'
app.config['SECRET_KEY'] = 'wai_c/23'  # Make sure this is strong in production
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Set session lifetime
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure cookies are sent over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Prevent CSRF attacks
app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # Refresh session on each request

db = SQLAlchemy(app)

# Flask-Mail configuration (Replace these with your actual SMTP server details)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '23ycnsale@gmail.com'
app.config['MAIL_PASSWORD'] = 'yctj uddk bqez nhqw'  # Use the app password generated from Gmail
mail = Mail(app)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# UserProgress model to store user progress data
class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    progress_data = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('progress', lazy=True))

# ContactMessage model to store contact form submissions
class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    subject = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=True)  # Optional rating

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('projects', lazy=True))

class CalendarActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(10), nullable=False)  # Store date in 'YYYY-MM-DD' format
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "date": self.date,
            "title": self.title,
            "description": self.description
        }

# Subscription model to store subscribed emails
class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return f'<Subscription {self.email}>'

# Session teardown to ensure sessions are cleared when the user leaves
@app.teardown_request
def teardown_session(exception=None):
    session.modified = True  # Ensure session is cleared or refreshed on request end
    return exception

# Ensure user is logged in
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"message": "Unauthorized!"}), 401
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# Admin check
def admin_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            return jsonify({"message": "Admin access required!"}), 403
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# Register route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', False)

    if not email or not username or not password:
        return jsonify({"message": "Email, username, and password are required!"}), 400

    existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
    if existing_user:
        return jsonify({"message": "Username or email already exists!"}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, email=email, password=hashed_password, is_admin=is_admin)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"}), 201

# Login route
@app.route('/login', methods=['POST'])
def login():
    if 'user_id' in session:
        return jsonify({"message": "Already logged in!", "redirect": "/user-page"}), 200

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password are required!"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid email or password!"}), 401

    session['user_id'] = user.id
    session['username'] = user.username
    session['is_admin'] = user.is_admin
    session.permanent = True

    if user.is_admin:
        return jsonify({"message": "Login successful!", "redirect": "/admin-dashboard"}), 200
    else:
        return jsonify({"message": "Login successful!", "redirect": "/user-page"}), 200

# User page route, protected by login
@app.route('/user', methods=['GET'])
@login_required
def user_page():
    return jsonify({"message": f"Welcome {session['username']} to the User Page!"}), 200

# Fetch user info route, protected by login
@app.route('/user-info', methods=['GET'])
@login_required
def user_info():
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({"message": "User not found!"}), 404

    # Return user's username and admin status
    return jsonify({
        "username": user.username,
        "is_admin": user.is_admin  # Include admin status in the response
    }), 200

# Admin dashboard route, protected by admin check
@app.route('/admin-dashboard', methods=['GET'])
@admin_required
def admin_dashboard():
    return jsonify({"message": "Welcome to the Admin Dashboard!"}), 200

# Logout route
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()  # Clear all session data
    return jsonify({"message": "Logged out successfully!", "redirect": "/"}), 200

# Post user progress, protected by login
@app.route('/user/<int:user_id>/post-progress', methods=['POST'])
@login_required
def post_user_progress(user_id):
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    progress = data.get('progress')

    if not all([title, description, progress]):
        return jsonify({"message": "All fields are required!"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found!"}), 404

    if session['user_id'] != user_id and not session.get('is_admin'):
        return jsonify({"message": "Unauthorized to post progress for this user!"}), 403

    progress_data_json = json.dumps({
        "title": title,
        "description": description,
        "progress": progress
    })

    new_progress = UserProgress(
        user_id=user_id,
        progress_data=progress_data_json,
        timestamp=datetime.utcnow()
    )

    try:
        db.session.add(new_progress)
        db.session.commit()
        return jsonify({"message": "Progress posted successfully!"}), 201
    except Exception as e:
        return jsonify({"message": "Error saving progress!", "error": str(e)}), 500

# Route to fetch user progress, protected by login
@app.route('/user-progress', methods=['GET'])
@login_required
def get_progress():
    user_id = session['user_id']
    progress_entries = UserProgress.query.filter_by(user_id=user_id).all()

    if not progress_entries:
        return jsonify({"message": "No progress found!"}), 404

    progress_list = [{
        "id": progress.id,
        "progress_data": json.loads(progress.progress_data),
        "timestamp": progress.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    } for progress in progress_entries]

    return jsonify({"progress": progress_list}), 200

# Route to delete user, protected by admin
@app.route('/user/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found!"}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "User deleted successfully!"}), 200

# Route to promote user to admin, protected by admin
@app.route('/user/<int:user_id>/promote', methods=['PUT'])
@admin_required
def promote_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found!"}), 404

    user.is_admin = True
    db.session.commit()

    return jsonify({"message": "User promoted to admin successfully!"}), 200

@app.route('/performance', methods=['GET'])
def performance():
    cpu_usage = psutil.cpu_percent()
    ram_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent

    performance_score = (100 - (cpu_usage + ram_usage + disk_usage) / 3)

    return jsonify({
        "performance": round(performance_score, 2)
    }), 200

@app.route('/users', methods=['GET'])
@admin_required  # Ensure this route is only accessible by admins
def get_users():
    users = User.query.all()
    users_list = [{
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin
    } for user in users]

    return jsonify(users_list), 200

# Route to submit contact form data
@app.route('/contact', methods=['POST'])
def submit_contact_form():
    data = request.get_json()

    name = data.get('name')
    email = data.get('email')
    subject = data.get('subject')
    message = data.get('message')
    rating = data.get('rating')

    if not all([name, email, subject, message]):
        return jsonify({"message": "All fields are required!"}), 400

    new_message = ContactMessage(
        name=name,
        email=email,
        subject=subject,
        message=message,
        rating=rating
    )

    try:
        db.session.add(new_message)
        db.session.commit()
        return jsonify({"message": "Message sent successfully!"}), 201
    except Exception as e:
        return jsonify({"message": "Error saving message!", "error": str(e)}), 500
    
# Route to get all messages, protected by admin check
@app.route('/admin/messages', methods=['GET'])
#@admin_required  # Ensure only admins can access this route
def get_messages():
    try:
        # Query all contact messages from the database
        messages = ContactMessage.query.all()

        # Prepare the list of messages in a serializable format
        messages_list = [{
            'id': message.id,
            'name': message.name,
            'email': message.email,
            'subject': message.subject,
            'message': message.message,
            'rating': message.rating
        } for message in messages]

        return jsonify({'messages': messages_list}), 200

    except Exception as e:
        return jsonify({'message': 'Failed to load messages', 'error': str(e)}), 500
    
# Route to delete a message by ID
@app.route('/admin/messages/<int:id>', methods=['DELETE'])
# @admin_required  # Ensure only admins can access this route
def delete_message(id):
    message = ContactMessage.query.get(id)  # Fetch the message by ID
    if not message:
        return jsonify({'error': 'Message not found'}), 404
    
    try:
        db.session.delete(message)  # Delete the message
        db.session.commit()  # Commit the changes
        return jsonify({'message': 'Message deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        return jsonify({'error': 'An error occurred while deleting the message.'}), 500

# Route to create a new project
@app.route('/new-project', methods=['POST'])
@admin_required  # Ensure only admins can access this route
def new_project():
    data = request.get_json()
    user_id = data.get('user_id')
    title = data.get('title')
    description = data.get('description')

    if not user_id or not title or not description:
        return jsonify({"message": "All fields are required!"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "Client (user) not found!"}), 404

    # Assuming you have a Project model to store project information
    new_project = Project(user_id=user_id, title=title, description=description)

    try:
        db.session.add(new_project)
        db.session.commit()
        return jsonify({"message": "Project created successfully!"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error creating project", "error": str(e)}), 500

# Route to get the total number of projects
@app.route('/projects/count', methods=['GET'])
@admin_required  # Ensure only admins can access this
def get_project_count():
    try:
        project_count = Project.query.count()  # Count the total number of projects
        return jsonify({"count": project_count}), 200
    except Exception as e:
        return jsonify({"message": "Error fetching project count", "error": str(e)}), 500

# Route to fetch all activities
@app.route('/activities', methods=['GET'])
@admin_required  # Only admins can fetch activities
def get_activities():
    try:
        activities = CalendarActivity.query.all()
        activities_list = [activity.to_dict() for activity in activities]
        return jsonify({"activities": activities_list}), 200
    except Exception as e:
        return jsonify({"message": "Error fetching activities", "error": str(e)}), 500

# Route to add a new activity
@app.route('/activities', methods=['POST'])
@admin_required  # Only admins can add activities
def add_activity():
    data = request.get_json()
    date = data.get('date')
    title = data.get('title')
    description = data.get('description')

    if not date or not title or not description:
        return jsonify({"message": "All fields are required!"}), 400

    new_activity = CalendarActivity(date=date, title=title, description=description)

    try:
        db.session.add(new_activity)
        db.session.commit()
        return jsonify({"message": "Activity added successfully!"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error adding activity", "error": str(e)}), 500

# Route to delete an activity
@app.route('/activities/<int:id>', methods=['DELETE'])
# @admin_required  # Only admins can delete activities
def delete_activity(id):
    activity = CalendarActivity.query.get(id)
    if not activity:
        return jsonify({"message": "Activity not found!"}), 404

    try:
        db.session.delete(activity)
        db.session.commit()
        return jsonify({"message": "Activity deleted successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error deleting activity", "error": str(e)}), 500

# Route to get the total number of activities
@app.route('/activities/count', methods=['GET'])
@admin_required  # Ensure only admins can access this
def get_activity_count():
    try:
        activity_count = CalendarActivity.query.count()  # Count the total number of activities
        return jsonify({"count": activity_count}), 200
    except Exception as e:
        return jsonify({"message": "Error fetching activity count", "error": str(e)}), 500

# Route to get the total number of messages
@app.route('/admin/messages/count', methods=['GET'])
@admin_required  # Ensure only admins can access this
def get_message_count():
    try:
        message_count = ContactMessage.query.count()  # Count the total number of messages
        return jsonify({"count": message_count}), 200
    except Exception as e:
        return jsonify({"message": "Error fetching message count", "error": str(e)}), 500

# Route to handle email subscriptions
@app.route('/subscribe', methods=['POST'])
def subscribe():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"message": "Email is required!"}), 400

    # Check if the email is already subscribed
    existing_subscription = Subscription.query.filter_by(email=email).first()
    if existing_subscription:
        return jsonify({"message": "Email is already subscribed!"}), 400

    new_subscription = Subscription(email=email)
    
    try:
        db.session.add(new_subscription)
        db.session.commit()
        return jsonify({"message": "Subscription successful!"}), 201
    except Exception as e:
        return jsonify({"message": "Failed to subscribe.", "error": str(e)}), 500

# Route to fetch all subscribed emails
@app.route('/subscriptions', methods=['GET'])
@admin_required  # Ensure only admins can access this route
def get_subscriptions():
    try:
        subscriptions = Subscription.query.all()
        emails = [subscription.email for subscription in subscriptions]
        return jsonify({"subscribers": emails}), 200
    except Exception as e:
        return jsonify({"message": "Error fetching subscribers", "error": str(e)}), 500

# Route to count the number of subscribed emails
@app.route('/subscriptions/count', methods=['GET'])
@admin_required  # Ensure only admins can access this route
def get_subscription_count():
    try:
        subscription_count = Subscription.query.count()  # Count total number of subscriptions
        return jsonify({"count": subscription_count}), 200
    except Exception as e:
        return jsonify({"message": "Error fetching subscription count", "error": str(e)}), 500

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip().lower()
    if not query:
        return jsonify({"message": "No search query provided", "results": []}), 400

    # Simulated indexed content from the site
    pages = [
        {"url": "/login", "title": "Login", "description": "Sign in to access your account"},
        {"url": "/register", "title": "Register", "description": "Create a new account on TEYORA"},
        {"url": "/about", "title": "About Us", "description": "Learn more about TEYORA and our team"},
        {"url": "/get-started", "title": "Get Started", "description": "Get started with TEYORA's digital solutions"},
        {"url": "/subscription", "title": "Subscription", "description": "Subscribe to our newsletter for updates"},
        {"url": "/category/website", "title": "Website Development", "description": "Custom website development services"},
        {"url": "/category/poster", "title": "Poster Design", "description": "Get professional posters designed by TEYORA"},
        {"url": "/category/blog", "title": "Blog", "description": "Explore insightful blogs on technology"},
        {"url": "/category/networking", "title": "Networking", "description": "Networking services to expand your business"},
        {"url": "/category/penetration-testing", "title": "Penetration Testing", "description": "Secure your systems with penetration testing services"},
        {"url": "/category/designing", "title": "Designing", "description": "Creative design solutions for your business"},
        {"url": "/policy", "title": "Privacy Policy", "description": "Read our privacy policy"},
        {"url": "/terms", "title": "Terms of Use", "description": "Read our terms of use"},
        {"url" : "/the_Team", "title": "Team" , "description" : "Get to know our team"}
    ]

    # Home page services
    sections = [
        {"url": "/", "title": "Fortify Your Digital Fortress", "description": "Cybersecurity services to safeguard your business"},
        {"url": "/", "title": "Crafting Digital Masterpieces", "description": "Expert web development services to build stunning websites"},
        {"url": "/", "title": "Your Tech Catalyst", "description": "Innovative solutions to drive business growth"},
        {"url": "/", "title": "Expand Your Network", "description": "Networking services to grow your business connections"},
        {"url": "/", "title": "Seamless Integration", "description": "AI integration services to streamline your business"}
    ]

    # Combine pages and sections
    searchable_content = pages + sections

    # Search logic: match the query with titles or descriptions
    results = []
    for content in searchable_content:
        if query in content['title'].lower() or query in content['description'].lower():
            results.append(content)
    return jsonify({"query": query, "results": results}), 200

@app.route('/search-in', methods=['GET'])
def search_in():
    query = request.args.get('query', '').strip().lower()
    if not query:
        return jsonify({"message": "No search query provided", "results": []}), 400

    # Simulate session or authentication mechanism
    # Here we assume that user role is stored in the session or JWT token
    # For now, let's simulate it with a static value. In a real application, it would be dynamically fetched.
    user_role = session.get('role', 'user')  # Assume 'user' is the default role, and 'admin' for admin users

    # Index for normal users
    normal_user_pages = [
        {"url": "/login", "title": "Login", "description": "Sign in to access your account"},
        {"url": "/register", "title": "Register", "description": "Create a new account on TEYORA"},
        {"url": "/about", "title": "About Us", "description": "Learn more about TEYORA and our team"},
        {"url": "/subscription", "title": "Subscription", "description": "Subscribe to our newsletter for updates"},
        {"url": "/category-in/website", "title": "Website Development", "description": "Custom website development services"},
        {"url": "/category-in/poster", "title": "Poster Design", "description": "Get professional posters designed by TEYORA"},
        {"url": "/category-in/blog", "title": "Blog", "description": "Explore insightful blogs on technology"},
        {"url": "/category-in/networking", "title": "Networking", "description": "Networking services to expand your business"},
        {"url": "/category-in/penetration-testing", "title": "Penetration Testing", "description": "Secure your systems with penetration testing services"},
        {"url": "/category-in/designing", "title": "Designing", "description": "Creative design solutions for your business"},
        {"url": "/policy", "title": "Privacy Policy", "description": "Read our privacy policy"},
        {"url": "/terms", "title": "Terms of Use", "description": "Read our terms of use"},
        {"url": "/user-progress", "title": "User Progress", "description": "Track your project progress as a user"},
        {"url": "/user-page", "title": "User Page", "description": "Manage your personal TEYORA account"}
    ]

    # Index for admin users (normal user pages + admin-only pages)
    admin_pages = normal_user_pages + [
        {"url": "/admin-dashboard", "title": "Admin Dashboard", "description": "Access the admin dashboard for TEYORA"},
        {"url": "/new_project", "title": "New Project", "description": "Create a new project as an admin"}
    ]

    # Determine which pages to search through based on the user's role
    if user_role == 'admin':
        searchable_pages = admin_pages
    else:
        searchable_pages = normal_user_pages

    # Search logic: Match the query with titles or descriptions
    results = []
    for page in searchable_pages:
        if (
            query in page['title'].lower() or
            query in page['description'].lower()
        ):
            results.append(page)

    return jsonify({"query": query, "results": results}), 200

# Temporary in-memory storage for OTPs (Consider using a persistent store in production)
otp_storage = {}

# Route to request OTP
@app.route('/forgot-password/request-otp', methods=['POST'])
def request_otp():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({"message": "Email not registered"}), 404

    otp = randint(1000, 9999)
    otp_expiry = datetime.now() + timedelta(minutes=3)  # OTP valid for 60 seconds

    # Save OTP and expiry in temporary storage
    otp_storage[email] = {'otp': otp, 'expiry': otp_expiry}
    
    # Send OTP email
    msg = Message(subject="Your OTP for Password Reset",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    msg.body = f"Your OTP is: {otp}. It will expire in 3 minutes."
    mail.send(msg)
    
    return jsonify({"message": "OTP sent successfully"}), 200

# Route to verify OTP
@app.route('/forgot-password/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp_provided = int(data.get('otp'))
    
    otp_info = otp_storage.get(email)
    
    if not otp_info:
        return jsonify({"message": "OTP request not found"}), 404
    
    if datetime.now() > otp_info['expiry']:
        return jsonify({"message": "OTP expired"}), 400
    
    if otp_provided != otp_info['otp']:
        return jsonify({"message": "Invalid OTP"}), 400

    return jsonify({"message": "OTP verified"}), 200

# Route to reset password
@app.route('/forgot-password/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('newPassword')
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Hash the new password
    hashed_password = generate_password_hash(new_password)
    user.password = hashed_password
    db.session.commit()
    
    # Invalidate the OTP after successful password reset
    if email in otp_storage:
        del otp_storage[email]

    return jsonify({"message": "Password reset successful"}), 200

from datetime import datetime, timedelta
from random import randint

# In-memory storage for OTP and temporary user data for Google registration
google_registration_storage = {}

# Route to handle Google registration and send OTP
@app.route('/register-google', methods=['POST'])
def register_google():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    # Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"message": "Email already registered"}), 409

    # Generate OTP and set expiry
    otp = randint(1000, 9999)
    otp_expiry = datetime.now() + timedelta(minutes=3)

    # Store the temporary user data with OTP
    google_registration_storage[email] = {
        'username': username,
        'password': generate_password_hash(password),
        'otp': otp,
        'otp_expiry': otp_expiry
    }

    # Send OTP to user's email
    msg = Message(subject="Your OTP for Google Registration",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    msg.body = f"Your OTP is: {otp}. It will expire in 3 minutes."
    mail.send(msg)

    return jsonify({"message": "OTP sent to your email for verification"}), 200

# Route to verify OTP and complete Google registration
@app.route('/verify-google-otp', methods=['POST'])
def verify_google_otp():
    data = request.get_json()
    email = data.get('email')
    otp_provided = int(data.get('otp'))

    # Check if the OTP and user data are in the temporary storage
    temp_user_data = google_registration_storage.get(email)
    if not temp_user_data:
        return jsonify({"message": "OTP request not found"}), 404

    # Check if OTP is valid
    if datetime.now() > temp_user_data['otp_expiry']:
        del google_registration_storage[email]  # Clean up expired data
        return jsonify({"message": "OTP expired"}), 400

    if otp_provided != temp_user_data['otp']:
        return jsonify({"message": "Invalid OTP"}), 400

    # Create a new user entry in the database with verified email
    new_user = User(
        username=temp_user_data['username'],
        email=email,
        password=temp_user_data['password']  # Already hashed
    )
    db.session.add(new_user)
    db.session.commit()

    # Clean up temporary storage after successful registration
    del google_registration_storage[email]

    return jsonify({"message": "Google registration verified and account created"}), 200


# Temporary storage for OTPs (consider using Redis or a database in production)
otp_storage = {}

# Route to request OTP for Google login
@app.route('/google-login-request', methods=['POST'])
def google_login_request():
    data = request.get_json()
    email = data.get('email')
    
    # Check if user exists in the database
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "Email not registered"}), 404
    
    # Generate OTP and set expiry time
    otp = randint(1000, 9999)
    otp_expiry = datetime.now() + timedelta(minutes=1)  # OTP valid for 60 seconds

    # Store OTP and expiry for this email
    otp_storage[email] = {'otp': otp, 'expiry': otp_expiry, 'role': user.is_admin}
    
    # Send OTP to user's email
    msg = Message(subject="Your OTP for Google Login",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    msg.body = f"Your OTP is: {otp}. It will expire in 60 seconds."
    mail.send(msg)

    return jsonify({"message": "OTP sent to your email"}), 200

# Route to verify OTP for Google login
from flask import session  # Import session if not already imported

# Route to verify OTP for Google login and log the user in
@app.route('/google-login-verify', methods=['POST'])
def google_login_verify():
    data = request.get_json()
    email = data.get('email')
    otp_provided = int(data.get('otp'))

    # Check if OTP is in the storage
    otp_info = otp_storage.get(email)
    if not otp_info:
        return jsonify({"message": "OTP request not found"}), 404
    
    # Validate OTP expiry and correctness
    if datetime.now() > otp_info['expiry']:
        del otp_storage[email]  # Clean up expired OTP
        return jsonify({"message": "OTP expired"}), 400

    if otp_provided != otp_info['otp']:
        return jsonify({"message": "Invalid OTP"}), 400

    # Find the user based on email to establish the session
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Create a session for the logged-in user
    session['user_id'] = user.id  # Store the user ID in the session
    session['is_admin'] = user.is_admin  # Store user role in session

    # Determine redirect URL based on role
    redirect_url = '/admin-dashboard' if user.is_admin else '/user-dashboard'

    # Clean up OTP after successful verification
    del otp_storage[email]

    return jsonify({"message": "OTP verified", "redirect": redirect_url}), 200

# Ensure tables are created before the app starts
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
