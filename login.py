# from flask import Blueprint, request, jsonify
# from pymongo import MongoClient
# from pymongo.server_api import ServerApi
# import bcrypt  # For password hashing
# from dbConnection import connect_to_mongodb  # Import the connect_to_mongodb function

# login_bp = Blueprint('login', __name__)

# # Connect to MongoDB
# client = connect_to_mongodb()
# if client:
#     # Perform operations using the client
#     # Example: users_collection = client.mydatabase.users
#     users_collection = client.FYP.users
# else:
#     print("Failed to connect to MongoDB!")

# @login_bp.route('/register', methods=['POST'])
# def register_user():
#     data = request.json
#     # Validate user data (you may want to add more validation)
#     if not data.get('email') or not data.get('password'):
#         return jsonify({"error": "Email and password are required"}), 400

#     # Check if email already exists
#     if users_collection.find_one({"email": data['email']}):
#         return jsonify({"error": "Email already registered"}), 400

#     # Hash password before storing it in the database
#     hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

#     # Add additional user data to be stored in the database
#     user_data = {
#         "name": data['name'],
#         "email": data['email'],
#         "mobile": data['mobile'],
#         "age": data['age'],
#         "sex": data['sex'],
#         "password": hashed_password
#     }

#     # Insert user data into MongoDB
#     users_collection.insert_one(user_data)
    
#     return jsonify({"message": "User registered successfully"}), 200


# @login_bp.route('/login', methods=['POST'])
# def login_user():
#     data = request.json
#     # Validate user data (you may want to add more validation)
#     if not data.get('email') or not data.get('password'):
#         return jsonify({"error": "Email and password are required"}), 400

#     # Find the user by email in the database
#     user = users_collection.find_one({"email": data['email']})

#     if user:
#         # Check if the provided password matches the hashed password stored in the database
#         if bcrypt.checkpw(data['password'].encode('utf-8'), user['password']):
#             # Password is correct, user is authenticated
#             return jsonify({"user": {"name": user['name'], "email": user['email']}}), 200
#         else:
#             # Password is incorrect
#             return jsonify({"error": "Invalid password"}), 401
#     else:
#         # User not found in the database
#         return jsonify({"error": "User not found"}), 404


from flask import Blueprint, request, jsonify, session
from flask_session import Session
from pymongo import MongoClient
import bcrypt  # For password hashing
from dbConnection import connect_to_mongodb  # Import the connect_to_mongodb function

login_bp = Blueprint('login', __name__)

# Connect to MongoDB
client = connect_to_mongodb()
if client:
    # Perform operations using the client
    # Example: users_collection = client.mydatabase.users
    users_collection = client.FYP.users
else:
    print("Failed to connect to MongoDB!")


@login_bp.route('/register', methods=['POST'])
def register_user():
    data = request.json
    # Validate user data (you may want to add more validation)
    if not data.get('email') or not data.get('password'):
        return jsonify({"error": "Email and password are required"}), 400

    # Check if email already exists
    if users_collection.find_one({"email": data['email']}):
        return jsonify({"error": "Email already registered"}), 400

    # Hash password before storing it in the database
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

    # Add additional user data to be stored in the database
    user_data = {
        "name": data['name'],
        "email": data['email'],
        "mobile": data['mobile'],
        "age": data['age'],
        "sex": data['sex'],
        "password": hashed_password
    }

    # Insert user data into MongoDB
    users_collection.insert_one(user_data)
    
    return jsonify({"message": "User registered successfully"}), 200


@login_bp.route('/login', methods=['POST'])
def login_user():
    data = request.json
    # Validate user data (you may want to add more validation)
    if not data.get('email') or not data.get('password'):
        return jsonify({"error": "Email and password are required"}), 400

    # Find the user by email in the database
    user = users_collection.find_one({"email": data['email']})

    if user:
        # Check if the provided password matches the hashed password stored in the database
        if bcrypt.checkpw(data['password'].encode('utf-8'), user['password']):
            # Password is correct, user is authenticated
            session['user'] = {"name": user['name'], "email": user['email']}  # Store user data in session
            # Check if a session is created
            if session:
                print("Session is created.")
                # Access session data if needed
                user_data = session.get('user')
                if user_data:
                    print("User data found in session:", user_data)
                else:
                    print("No user data found in session.")
            else:
                    print("Session is not created.")

            return jsonify({"user": {"name": user['name'], "email": user['email']}}), 200
        else:
            # Password is incorrect
            return jsonify({"error": "Invalid password"}), 401
    else:
        # User not found in the database
        return jsonify({"error": "User not found"}), 404


# Check if a session is created
if session:
    print("Session is created.")
    # Access session data if needed
    user_data = session.get('user')
    if user_data:
        print("User data found in session:", user_data)
    else:
        print("No user data found in session.")
else:
    print("Session is not created.")
