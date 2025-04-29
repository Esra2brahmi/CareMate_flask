from flask import Flask, request, jsonify, send_from_directory, url_for
from flask_pymongo import PyMongo
from flask_cors import CORS
import os
from flask_pymongo import PyMongo
from config import Config
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from bson.objectid import ObjectId
import jwt
from functools import wraps

app = Flask(__name__)
app.config.from_object(Config)

# Configure the upload folder
app.config['UPLOAD_FOLDER'] = 'uploads/'  # Directory to store uploaded files
# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Enable Cross-Origin Resource Sharing (CORS)
CORS(app)


@app.route('/')
def index():
    return jsonify({'message': 'Welcome to the Flask API'})

# Configure Flask-Mail
app.config.update(
    MAIL_SERVER='smtp.gmail.com',      # Replace with your mail server
    MAIL_PORT=587,                       # Replace with your mail server port
    MAIL_USE_TLS=True,
    MAIL_USERNAME='esrabrahmii@gmail.com',  # Replace with your email
    MAIL_PASSWORD='Rgh@2020'      # Replace with your email password
)
mail = Mail(app)


# Initialize PyMongo with the Flask app
mongo = PyMongo(app)
db = mongo.db  # Access the MongoDB database defined in MONGO_URI




# Serializer for generating tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])





# Add this decorator for protected routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = db.users.find_one({'email': data['email']})
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401

        return f(current_user, *args, **kwargs)
    return decorated


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
    role=data.get('role')

    # Validate input
    if not name or not email or not password or not role:
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
        'password': hashed_password,
        'role':role
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
    role = data.get('role')

    # Validate input
    if not email or not password or not role:
        return jsonify({'status': 'fail', 'message': 'Missing fields'}), 400

    # Find the user by email
    user = db.users.find_one({'email': email})
    if user and check_password_hash(user['password'], password):
        # In a real-world app, you might return a token here
        return jsonify({
            'status': 'success',
            'message': 'Logged in successfully',
            'user': {'_id': str(user['_id']),'name': user['name'], 'email': user['email'],'role': user['role']}
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


# ---------------------------
# Endpoint: file upload
# ---------------------------
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'}), 400

    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    
    try:
        file.save(file_path)
        return jsonify({'success': True, 'message': 'Upload and move success'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error uploading file: {str(e)}'}), 500


# ---------------------------
# Endpoint: get file upload
# ---------------------------
@app.route('/uploads/<filename>')
def get_uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ---------------------------
# Endpoint: list uploaded files
# ---------------------------

@app.route('/uploads/list', methods=['GET'])
def list_uploaded_files():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return {"images": files}


# ---------------------------
# Endpoint: Book Appointment
# ---------------------------
@app.route('/book-appointment', methods=['POST'])
def book_appointment():
    data = request.get_json(silent=True) or request.form
    name = data.get('name')
    age = data.get('age')
    address = data.get('address')
    gender = data.get('gender')
    photo=data.get('photo')
    phone = data.get('phone')
    email = data.get('email')
    date_rdv = data.get('date_rdv')  # Date du rendez-vous
    doctor_id = data.get('doctor_id')
     # verify data
    if not all([name, age, address, gender,photo, phone, email, date_rdv,doctor_id]):
        return jsonify({'status': 'fail', 'message': 'Missing fields'}), 400
     # First check if user exists
    user = db.users.find_one({'email': email})
    if not user:
        return jsonify({
            'status': 'error',
            'code': 'USER_NOT_REGISTERED',  # Specific error code
            'message': 'This email is not registered. Please sign up first.'
        }), 403
    
    # insert patients in the DB
    patient_id = db.appointments.insert_one({  
    'name': name,  
    'age': age,  
    'address': address,  
    'gender': gender,  
    'photo':photo,
    'phone': phone,  
    'email': email,  
    'date_rdv': date_rdv,
    'doctor_id':doctor_id,
    'isAccept': False

    }).inserted_id 
    return jsonify({
        'status': 'success',
        'message': 'Appointment booked successfully',
        'patient_id': str(patient_id)
    }), 201

# -----------------------------------------------
# Endpoint: Get  Appointment Requests 
# -----------------------------------------------
@app.route('/appointments', methods=['GET'])
def getAppointmentsRequest():
    appointments = list(db.appointments.find({ "isAccept": False}, {"_id": 0}))
    return jsonify(appointments), 200


# ---------------------------------
# Endpoint: Get accepted Appointment (patientList)
# ---------------------------------
@app.route('/appointments/accepted', methods=['GET'])
def get_accepted_appointments():
    accepted_appointments = list(db.appointments.find({"isAccept": True}, {"_id": 0}))
    return jsonify(accepted_appointments), 200

# ---------------------------------
# Endpoint: Accept Appointment
# ---------------------------------
@app.route('/accept-appointment-by-email/<email>', methods=['PUT'])
def accept_appointment_by_email(email):
    result = db.appointments.update_one(
        {"email": email},  # find appointment with  email
        {"$set": {"isAccept": True}}  # Update isAccept to True
    )
    if result.matched_count == 0:
        return jsonify({'status': 'fail', 'message': 'Appointment not found'}), 404
    
    return jsonify({'status': 'success', 'message': 'Appointment accepted'}), 200

# ---------------------------------
# Endpoint: Delete Appointment
# ---------------------------------
@app.route('/delete-appointment-by-email/<email>', methods=['DELETE'])
def delete_appointment_by_email(email):
    result = db.appointments.delete_one({"email": email})
    # Vérifier si un document a été supprimé
    if result.deleted_count > 0:
        return jsonify({"message": "Appointment deleted successfully"}), 200
    else:
        return jsonify({"error": "Appointment not found"}), 404

# ---------------------------------
# Endpoint: Reschedule Appointment
# ---------------------------------
@app.route('/reschedule-appointment-by-email', methods=['PUT'])
def reschedule_appointment():
    data = request.json
    email = data.get("email")
    new_date = data.get("date_rdv")
    if not email or not new_date :
        return jsonify({"message": "Please provide a new date"}), 400

    # Mettre à jour la date de rendez-vous dans la base de données
    result = mongo.db.appointments.update_one(
        {"email": email},
        {"$set": {"date_rdv": new_date}}
    )
    if result.modified_count > 0:
        return jsonify({"message": "Appointment rescheduled successfully"}), 200
    else:
        return jsonify({"message": "No changes made or patient not found"}), 404


# ---------------------------------
# Endpoint: create doctor
# ---------------------------------

@app.route('/doctors', methods=['POST'])
def add_doctor():
    name = request.form.get('name')
    email = request.form.get('email')
    speciality = request.form.get('speciality')
    description = request.form.get('description')
    location = request.form.get('location')
    phoneNumber = request.form.get('phoneNumber')
    imageDoc = request.files.get('imageDoctor')
    imageServ = request.files.get('imageService')

    if not all([name, email, speciality, description, location,phoneNumber]):
        return jsonify({'status': 'fail', 'message': 'All fields are required'}), 400

    imageDoctor = ''
    if imageDoc:
        image_filename = f"{name.replace(' ', '_')}_{imageDoc.filename}"
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
        imageDoc.save(image_path)
        imageDoctor = url_for('get_uploaded_file', filename=image_filename, _external=True)

    imageService = ''
    if imageServ:
        image_filename = f"{name.replace(' ', '_')}_{imageServ.filename}"
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
        imageServ .save(image_path)
        imageService = url_for('get_uploaded_file', filename=image_filename, _external=True)

    doctor_id = db.doctors.insert_one({
        'name': name,
        'email': email,
        'speciality': speciality,
        'description': description,
        'location': location,
        'phoneNumber' : phoneNumber,
        'imageDoctor': imageDoctor,
        'imageService': imageService
    }).inserted_id

    return jsonify({'status': 'success', 'doctor_id': str(doctor_id)}), 201
# ---------------------------------
# Endpoint: get All doctors
# ---------------------------------
@app.route('/doctors', methods=['GET'])
def get_doctors():
    doctors = list(db.doctors.find())
    for doc in doctors:
        doc['_id'] = str(doc['_id'])  # Convert ObjectId to string
    return jsonify(doctors), 200

# ---------------------------------
# Endpoint: get doctor by id
# ---------------------------------
@app.route('/doctors/<_id>',methods=['GET'])
def get_doctors_by_id(_id):
 try:
    doctor=db.doctors.find_one({'_id':ObjectId(_id)})
    if doctor:
        doctor['_id']=str(doctor['_id'])
        return jsonify(doctor),200
    else:
        return jsonify({"error":"cannot fetching doctor"}),404
 except Exception as e:
     return jsonify({"error":str(e)}),400


# ---------------------------------
# Endpoint: Get doctor IDs by patient email (unique and approved appointments)
# ---------------------------------
@app.route('/patient-doctors', methods=['GET'])
@token_required
def get_patient_doctors(current_user):
    if current_user['role'] != 'patient':
        return jsonify({'status': 'fail', 'message': 'Unauthorized access'}), 403
    
    # Find all approved appointments for this patient
    appointments = list(db.appointments.find({
        'email': current_user['email'],
        'isAccept': True
    }))
    
    # Extract unique doctor IDs
    doctor_ids = []
    seen_doctors = set()
    
    for appt in appointments:
        doctor_id = appt.get('doctor_id')
        if doctor_id and doctor_id not in seen_doctors:
            seen_doctors.add(doctor_id)
            doctor_ids.append(doctor_id)
    
    return jsonify({
        'status': 'success',
        'doctor_ids': doctor_ids
    }), 200




if __name__ == '__main__':
    app.run(debug=True)
