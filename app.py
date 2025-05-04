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
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

from bson.objectid import ObjectId

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
    MAIL_USERNAME='rawiaghrairi@gmail.com',  # Replace with your email
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
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'status': 'fail', 'message': 'Invalid credentials'}), 401

    # Generate JWT token (valid for 24 hours)
    token = jwt.encode(
        {
            'email': user['email'],
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(minutes=10)  # Expiration time
        },
        app.config['SECRET_KEY'],  # Ensure this is set in your Flask app config
        algorithm="HS256"
    )
    return jsonify({
        'status': 'success',
        'message': 'Logged in successfully',
        'user': {
            '_id': str(user['_id']),
            'name': user['name'],
            'email': user['email'],
            'role': user['role']
        },
        'access_token': token  # ⚠️ Critical: Return the token!
    }), 200
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
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=True  # 👈 Ce paramètre force le téléchargement
    )
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
    try:
        # Vérifiez si c'est FormData
        if request.files:
            photo = request.files.get('photo')
            photo_filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            photo.save(photo_path)
            photo_url = url_for('get_uploaded_file', filename=photo_filename, _external=True)
        else:
            return jsonify({'status': 'fail', 'message': 'Photo is required'}), 400

        # Récupérez les autres données
        name = request.form.get('name')
        age = request.form.get('age')
        address = request.form.get('address')
        gender = request.form.get('gender')
        phone = request.form.get('phone')
        email = request.form.get('email')
        date_rdv = request.form.get('date_rdv')
        doctor_id = request.form.get('doctor_id')

        # Vérification des champs
        required_fields = [name, age, address, gender, phone, email, date_rdv, doctor_id]
        if not all(required_fields):
            return jsonify({'status': 'fail', 'message': 'Missing fields'}), 400

        # Insertion dans la base de données
        appointment_data = {
            'name': name,
            'age': age,
            'address': address,
            'gender': gender,
            'photo': photo_url,
            'phone': phone,
            'email': email,
            'date_rdv': date_rdv,
            'doctor_id': str(doctor_id),
            'isAccept': False,
            'created_at': datetime.utcnow()
        }

        patient_id = db.appointments.insert_one(appointment_data).inserted_id

        return jsonify({
            'status': 'success',
            'message': 'Appointment booked successfully',
            'patient_id': str(patient_id)
        }), 201

    except Exception as e:
        print(f"Error booking appointment: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
# -----------------------------------------------
# Endpoint: Get Appointment Requests 
# -----------------------------------------------
@app.route('/appointments', methods=['GET'])
@token_required
def getAppointmentsRequest(current_user):
    if current_user['role'] != 'doctor':
        return jsonify({'status': 'fail', 'message': 'Unauthorized access'}), 403
    
    doctor = db.doctors.find_one({
        'email': current_user['email']
    })
    
    if not doctor:
        return jsonify({'status': 'fail', 'message': 'Doctor not found'}), 404
    
    appointments = list(db.appointments.find({
        'doctor_id': str(doctor['_id']),
        'isAccept': False
    }))
    
    # Convertir les ObjectId en strings pour la sérialisation JSON
    for appt in appointments:
        appt['_id'] = str(appt['_id'])
        if 'doctor_id' in appt:
            appt['doctor_id'] = str(appt['doctor_id'])
    
    return jsonify({
        'status': 'success',
        'appointments': appointments
    }), 200
# ---------------------------------
# Endpoint: Get accepted Appointment (patientList)
# ---------------------------------
@app.route('/appointments/accepted', methods=['GET'])
@token_required
def get_accepted_appointments(current_user):
    if current_user['role'] != 'doctor':
        return jsonify({'status': 'fail', 'message': 'Unauthorized access'}), 403
    
    doctor = db.doctors.find_one({
        'email': current_user['email']
    })
    
    if not doctor:
        return jsonify({'status': 'fail', 'message': 'Doctor not found'}), 404
    
    accepted_appointments = list(db.appointments.find({
        'doctor_id': str(doctor['_id']),
        'isAccept': True
    }))
    # Convertir les ObjectId en strings pour la sérialisation JSON
    for appt in accepted_appointments:
        appt['_id'] = str(appt['_id'])
        if 'doctor_id' in appt:
            appt['doctor_id'] = str(appt['doctor_id'])
    
    return jsonify({
        'status': 'success',
        'appointments': accepted_appointments
    }), 200
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
    phone=request.form.get('phone'),
    imageDoc = request.files.get('imageDoctor')
    imageServ = request.files.get('imageService')

    if not all([name, email, speciality, description, location,phone]):
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
        'imageDoctor': imageDoctor,
        'imageService': imageService,
        'phone' : phone
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
    # 1. Récupérer tous les rendez-vous approuvés
    appointments = list(db.appointments.find({
        'email': current_user['email'],
        'isAccept': True
    }))
    # 2. Créer une liste de tous les médecins avec leurs rendez-vous
    doctors_data = []
    doctor_ids = []
    seen_doctors = set()
    for appt in appointments:
        doctor_id = appt.get('doctor_id')
        if doctor_id and doctor_id not in seen_doctors:
            seen_doctors.add(doctor_id)
            doctor_ids.append(doctor_id)
    for ids in doctor_ids:  
        try:
            # Récupérer les infos du médecin
            doctor = db.doctors.find_one({'_id': ObjectId(ids)})
            if doctor:
                # Ajouter les détails du rendez-vous au médecin
                doctor_data = {
                    'ids': str(doctor['_id']),
                    'name': doctor.get('name'),
                    'email': doctor.get('email'),
                    'speciality': doctor.get('speciality'),
                    'description': doctor.get('description'),
                    'location': doctor.get('location'),
                    'imageDoctor': doctor.get('imageDoctor'),  # Ajoutez la date du RDV
                    'imageService': doctor.get('imageService'),  # Ajoutez l'ID du rendez-vous
                    'phone': doctor.get('phone')
                }
                doctors_data.append(doctor_data)
        except:
            continue
    
    return jsonify({
        'status': 'success',
        'count': len(doctors_data),
        'doctors': doctors_data  # Retourne tous les médecins avec leurs rendez-vous
    }), 200
# Endpoint pour créer un événement
# ---------------------------------
@app.route('/events', methods=['POST'])
def create_event():
    data = request.get_json()
    if not data or not data.get('title') or not data.get('start'):
        return jsonify({'status': 'fail', 'message': 'Missing required fields'}), 400
    
    event_id = db.events.insert_one({
        'title': data['title'],
        'start': data['start'],
        'end': data.get('end'),
        'allDay': data.get('allDay', False),
        'created_at': datetime.utcnow()
    }).inserted_id
    
    return jsonify({
        'status': 'success',
        'event': {
            'id': str(event_id),
            'title': data['title'],
            'start': data['start'],
            'end': data.get('end'),
            'allDay': data.get('allDay', False)
        }
    }), 201

# -------------------------------------------
# Endpoint pour récupérer tous les événements
# -------------------------------------------
@app.route('/events', methods=['GET'])
def get_events():
    events = list(db.events.find({}, {'_id': 0, 'id': {'$toString': '$_id'}, 'title': 1, 'start': 1, 'end': 1, 'allDay': 1}))
    return jsonify(events), 200
# -------------------------------------------
# Endpoint create dignostics file
# -------------------------------------------
@app.route('/diagnostics', methods=['POST'])
@token_required
def add_diagnostics_File(current_user):
    if current_user['role'] != 'patient':
        return jsonify({'status': 'fail', 'message': 'Unauthorized access'}), 403
    try:
        # 1. Récupérer les données du formulaire
        filname = request.form.get('filname')
        doctor_id = request.form.get('doctor_id')
        image = request.files.get('image')
        
        # 3. Vérifier les champs obligatoires
        if not all([filname, doctor_id]):
            return jsonify({'status': 'fail', 'message': 'Missing required fields'}), 400
         # 4. Chercher un rendez-vous correspondant à ce médecin et cet email
        appointment = db.appointments.find_one({
            'email':current_user['email'],
            'isAccept':True
        })
        # Exemple temporaire à ajouter dans ton Flask ou test directement dans MongoDB Compass
        print(appointment)
        print(current_user['email'])
        if not appointment:
            return jsonify({
                'status': 'fail', 
                'message': 'No appointment found for this doctor and patient'
            }), 404

        # 5. Récupérer le patient_id depuis le rendez-vous
        patient_id = str(appointment['_id'])  # ou appointment['patient_id'] selon votre schéma
        # 6. Traitement du fichier image
        DiagnosticFile = ''
        if image:
            image_filename = f"{filname.replace(' ', '_')}_{image.filename}"
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image.save(image_path)
            DiagnosticFile = url_for('get_uploaded_file', filename=image_filename, _external=True)
            # 7. Enregistrement dans la base de données
        file_id = db.file.insert_one({
            'filname': filname,
            'doctor_id': appointment['doctor_id'],
            'patient_id': patient_id,
            'DiagnosticFile': DiagnosticFile,
            'patient_id': patient_id  # Stocker aussi l'ID du rendez-vous si besoin
        }).inserted_id

        return jsonify({
            'status': 'success',
            'file_id': str(file_id),
            'patient_id': patient_id
        }), 201
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
# ---------------------------------------------------
# Endpoint get dignostics by dictor_id and patient_id
# ----------------------------------------------------
@app.route('/FilePatient', methods=['GET'])
@token_required
def get_diagnostics_File_by_patientId(current_user):
    if current_user['role'] != 'patient':
        return jsonify({'status': 'fail', 'message': 'Unauthorized access'}), 403
    try:
        print("current_user:", current_user)

        # Chercher un rendez-vous correspondant à ce patient
        appointment = db.appointments.find_one({
            'email': current_user['email'],
            'isAccept': True
        })

        print("Appointment trouvé:", appointment)

        if not appointment:
            return jsonify({
                'status': 'fail',
                'message': 'No appointment found for this patient'
            }), 404

        # Vérification du contenu des ID
        print("doctor_id:", appointment.get('doctor_id'))
        print("patient_id:", appointment.get('patient_id'))

        files = list(db.file.find({
            'doctor_id': appointment['doctor_id'],
            'patient_id': str(appointment['_id'])
        }, {
            '_id': 0
        }))

        print("Fichiers trouvés:", files)

        return jsonify(files), 200

    except Exception as e:
        import traceback
        traceback.print_exc()  # Montre la trace complète de l'erreur
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
# ---------------------------------
# Endpoint delete dignostics by id
# ---------------------------------
@app.route('/diagnostics/<file_id>', methods=['DELETE'])
@token_required
def delete_diagnostics_file(current_user, file_id):
    if current_user['role'] != 'patient':
        return jsonify({'status': 'fail', 'message': 'Unauthorized access'}), 403
    try:
        # Vérifier si le fichier existe
        file_data = db.file.find_one({'_id': file_id})
        if not file_data:
            return jsonify({'status': 'fail', 'message': 'File not found'}), 404
        
        # Supprimer le fichier physique si existe
        if 'DiagnosticFile' in file_data:
            filename = file_data['DiagnosticFile'].split('/')[-1]  # Récupère le nom de fichier
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                os.remove(file_path)

        # Supprimer l'entrée dans la base MongoDB
        db.file.delete_one({'_id': file_id})

        return jsonify({'status': 'success', 'message': 'File deleted'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
# ---------------------------------------------------
# Endpoint get dignostics by dictor_id and patient_id
# ----------------------------------------------------


@app.route('/FileDoctor', methods=['GET'])
@token_required
def get_diagnostics_File_by_doctorId(current_user):
    if current_user['role'] != 'doctor':
        return jsonify({'status': 'fail', 'message': 'Unauthorized access'}), 403
    try:
        print("current_user:", current_user)

        # Trouver le docteur
        doctor = db.doctors.find_one({
            'email': current_user['email']
        })
        if not doctor:
            return jsonify({'status': 'fail', 'message': 'Doctor not found'}), 404

        doctor_id = str(doctor['_id'])  # Convertir en string
        print("doctor_id:", doctor_id)
        # Trouver un rendez-vous accepté
        appointment = db.appointments.find_one({
            'doctor_id':doctor_id,  # ou simplement doctor['_id']
            'isAccept': True
        })
        if not appointment:
            return jsonify({'status': 'fail', 'message': 'No accepted appointment found for this doctor'}), 404

        patient_id = str(appointment['_id'])  # Convertir aussi en string

        # Rechercher les fichiers
        files = list(db.file.find({
            'doctor_id': doctor_id,      # string dans la collection file
            'patient_id': patient_id     # string dans la collection file
        }, {
            '_id': 0
        }))


        print("patient_id:", patient_id)
        print("Fichiers trouvés:", files)

        return jsonify(files), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
    
