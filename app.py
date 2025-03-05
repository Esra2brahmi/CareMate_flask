from flask import Flask, request, jsonify, url_for
from flask_pymongo import PyMongo
from flask_cors import CORS
from config import Config
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

app = Flask(__name__)
app.config.from_object(Config)
@app.route('/')
def index():
    return jsonify({'message': 'Welcome to the Flask API'})

# Configure Flask-Mail
app.config.update(
    MAIL_SERVER='smtp.gmail.com',      # Replace with your mail server
    MAIL_PORT=587,                       # Replace with your mail server port
    MAIL_USE_TLS=True,
    MAIL_USERNAME='esrabrahmii@gmail.com',  # Replace with your email
    MAIL_PASSWORD='cppsczwrdrvaphmx'      # Replace with your email password
)
mail = Mail(app)
# Enable Cross-Origin Resource Sharing (CORS)
CORS(app)

# Initialize PyMongo with the Flask app
mongo = PyMongo(app)
db = mongo.db  # Access the MongoDB database defined in MONGO_URI

# Serializer for generating tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ---------------------------
# Endpoint: User Registration
# ---------------------------
@app.route('/register', methods=['POST'])
def register():
    # Accept JSON data or form data
    data = request.get_json(silent=True) or request.form
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    # Validate input
    if not name or not email or not password:
        return jsonify({'status': 'fail', 'message': 'Missing fields'}), 400

    # Check if the user already exists in the database
    if db.users.find_one({'email': email}):
        return jsonify({'status': 'fail', 'message': 'User already exists'}), 409

    # Hash the password before storing
    hashed_password = generate_password_hash(password)

    # Insert the new user document
    user_id = db.users.insert_one({
        'name': name,
        'email': email,
        'password': hashed_password
    }).inserted_id

    return jsonify({
        'status': 'success',
        'message': 'User registered',
        'user_id': str(user_id)
    }), 201

# ---------------------------
# Endpoint: User Login
# ---------------------------
@app.route('/login', methods=['POST'])
def login():
    # Accept JSON data or form data
    data = request.get_json(silent=True) or request.form
    email = data.get('email')
    password = data.get('password')

    # Validate input
    if not email or not password:
        return jsonify({'status': 'fail', 'message': 'Missing fields'}), 400

    # Find the user by email
    user = db.users.find_one({'email': email})
    if user and check_password_hash(user['password'], password):
        # In a real-world app, you might return a token here
        return jsonify({
            'status': 'success',
            'message': 'Logged in successfully',
            'user': {'name': user['name'], 'email': user['email']}
        }), 200
    else:
        return jsonify({'status': 'fail', 'message': 'Invalid credentials'}), 401

# ---------------------------
# Endpoint: Request Password Reset
# ---------------------------
@app.route('/reset-password', methods=['POST'])
def request_reset_password():
    data = request.get_json(silent=True) or request.form
    email = data.get('email')

    if not email:
        return jsonify({'status': 'fail', 'message': 'Missing email field'}), 400

    user = db.users.find_one({'email': email})
    if not user:
        return jsonify({'status': 'fail', 'message': 'User not found'}), 404

    # Generate a secure token valid for 1 hour (3600 seconds)
    token = serializer.dumps(email, salt='password-reset-salt')
    
    # Create the reset URL. In production, use your actual front-end URL.
    # Frontend reset page URL instead of backend API URL
    reset_url = f"http://localhost:8100/reset-password/{token}"


    # Send the reset email
    try:
        msg = Message("Password Reset Request",
              sender=app.config['MAIL_USERNAME'],
              recipients=[email])
        msg.html = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2>Password Reset Request</h2>
            <p>To reset your password, please click the link below:</p>
            <p><a href="{reset_url}" style="background: #007bff; color: #ffffff; padding: 10px 15px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
            <p>If you did not request a password reset, please ignore this email.</p>
        </body>
        </html>
        """
        mail.send(msg)

    except Exception as e:
        return jsonify({'status': 'fail', 'message': f'Error sending email: {str(e)}'}), 500

    return jsonify({
        'status': 'success',
        'message': 'A reset password link has been sent to your email'
    }), 200

# ---------------------------
# Endpoint: Reset Password with Token
# ---------------------------
@app.route('/reset-password/<token>', methods=['POST'])
def reset_with_token(token):
    data = request.get_json(silent=True) or request.form
    new_password = data.get('password')

    if not new_password:
        return jsonify({'status': 'fail', 'message': 'Missing new password field'}), 400

    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        return jsonify({'status': 'fail', 'message': 'The token has expired'}), 400
    except BadSignature:
        return jsonify({'status': 'fail', 'message': 'Invalid token'}), 400

    user = db.users.find_one({'email': email})
    if not user:
        return jsonify({'status': 'fail', 'message': 'User not found'}), 404

    hashed_password = generate_password_hash(new_password)
    db.users.update_one({'email': email}, {'$set': {'password': hashed_password}})

    return jsonify({
        'status': 'success',
        'message': 'Your password has been updated'
    }), 200


if __name__ == '__main__':
    app.run(debug=True)
