from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_cors import CORS
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object(Config)
@app.route('/')
def index():
    return jsonify({'message': 'Welcome to the Flask API'})

# Enable Cross-Origin Resource Sharing (CORS)
CORS(app)

# Initialize PyMongo with the Flask app
mongo = PyMongo(app)
db = mongo.db  # Access the MongoDB database defined in MONGO_URI

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

if __name__ == '__main__':
    app.run(debug=True)
