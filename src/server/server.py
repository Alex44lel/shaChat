import sqlite3
import uuid
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, send

from datetime import datetime, timedelta
from encryption import Encryption
from jsonManager import JsonManager


class ChatApp:
    def __init__(self):

        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app)
        # on initialization private and public keys are generated for asymetric encryption if they do not exists

        self.encryption = Encryption()
        self.json_keys = JsonManager("json_keys.json")
        self.db_conexion = sqlite3.connect(
            "shachat.db", check_same_thread=False)
        self.db_manager = self.db_conexion.cursor()

        # check if tables exist

        self.db_manager.execute(
            '''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, salt TEXT, session_token TEXT, session_token_date TEXT, sym_key TEXT)''')
        self.db_conexion.commit()

        self._create_restfull_routes()

    def run(self):
        self.socketio.run(self.app, host="localhost", port=5000, debug=True)

    # cripto----
    def _create_restfull_routes(self):
        @self.app.route('/get-public-key', methods=['GET'])
        def getPublicKey():
            key = self.encryption.export_public_key()
            return jsonify({"public-key": key}), 200

        @self.app.route('/receive-symmetric-key-from-client', methods=['POST'])
        def receiveSymmetricKeyFromClient():
            data = self.encryption.decrypt_body(
                request, "asym", "request")
            print(data)
            username = data.get('username')
            user_id = data.get('user_id')
            sym_key = data.get('sym_key')
            print("THIS IS THE KEY IN THE SERVER:", sym_key)

            print(username)
            try:
                self.db_manager.execute('UPDATE users SET sym_key=? WHERE username=?', (
                    sym_key, username))
                self.db_conexion.commit()
                # sym key is stored on a json for quick access and on databse as well, might delete database storage later
                self.json_keys.add_entry(str(user_id), sym_key)
                return jsonify({'message': 'Sym key received'}), 200
            except sqlite3.IntegrityError:
                return jsonify({'message': 'Error saving sym key'}), 409

        @self.app.route("/get-all-users-names/<string:user_id>", methods=["GET"])
        def getAllUserNames(user_id):
            try:
                result = self.db_manager.execute(
                    'SELECT id, username FROM users WHERE id != ?', (user_id,)).fetchall()

                print("THIS IS THE KEY IN THE SERVER:",
                      self.json_keys.search_entry(user_id))

                res = self.encryption.get_encrypted_body(
                    {"all_users": result}, "sym", self.json_keys.search_entry(user_id), "server")

                return jsonify(res), 200
            except sqlite3.Error:
                jsonify({'message': 'Error in the database'}), 401

        @self.app.route('/register', methods=['POST'])
        def register():
            data = self.encryption.decrypt_body(request, "asym", "request")
            username = data.get('username')
            password = data.get('password')
            hashed_password, salt = self.encryption.hash_salt(password, None)

            try:
                self.db_manager.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)', (
                    username, hashed_password, salt))
                self.db_conexion.commit()
                return jsonify({'message': 'Registration successful'}), 201
            except sqlite3.IntegrityError:
                return jsonify({'message': 'Username already exists'}), 409

        @self.app.route('/check-session-token', methods=['POST'])
        def checkSessionToken():
            # get token from the database
            user_public_key = request.get_json().get("user_public_key")
            data = self.encryption.decrypt_body(request, "asym", "request")
            session_token = data["session_token"]
            print("USER PUBLIC KEY:", user_public_key)

            try:
                result = self.db_manager.execute('SELECT id,username,session_token_date FROM users WHERE session_token = ?', (
                    session_token,))
                result = self.db_manager.fetchone()
                print("result", result)
                # check the date and determine if it is valid
                if not result:
                    return jsonify({"message": "Invalid session token"}), 401

                print(result)
                user_id = result[0]
                username = result[1]
                session_token_date_string = result[2]

                print(session_token_date_string)
                session_token_date = datetime.strptime(
                    session_token_date_string, '%Y-%m-%d %H:%M:%S')

                current_time = datetime.now()
                token_expiration_date = session_token_date + \
                    timedelta(seconds=20)

                if current_time > token_expiration_date:
                    print(current_time, token_expiration_date)
                    res_encrypted = self.encryption.get_encrypted_body(
                        {"message": "Session token is expired, ohhh :("}, "asym", user_public_key)
                    return jsonify(res_encrypted), 401
                # Token is valid

                res_encrypted = self.encryption.get_encrypted_body(
                    {"message": "Session token is valid, lets goooo", "user_id": user_id, "username": username}, "asym", user_public_key)
                return jsonify(res_encrypted), 200

            except sqlite3.Error as e:  # complete the except
                print(f"Database error: {e}")
                res_encrypted = self.encryption.get_encrypted_body(
                    {"message": "Invalid session token"}, "asym", user_public_key)
                return jsonify(res_encrypted), 401

                # return jsonify({}), 200

        @self.app.route('/logout', methods=['POST'])
        def logout():
            user_public_key = request.get_json().get("user_public_key")
            data = self.encryption.decrypt_body(request, "asym", "request")
            session_token = data.get('session_token')
            user_id = data.get('user_id')

            if (user_id):
                # delete symetric key
                self.json_keys.delete_entry(user_id)
            try:
                cursor = self.db_manager.execute(
                    'UPDATE users SET session_token=? WHERE session_token=?', (None, session_token))
                if cursor.rowcount == 0:
                    raise ValueError("Session token not found.")
                self.db_conexion.commit()
                res_encrypted = self.encryption.get_encrypted_body(
                    {"message": "Succesfully log out"}, "asym", user_public_key)
                return jsonify(res_encrypted), 200

            except Exception as e:
                res_encrypted = self.encryption.get_encrypted_body(
                    {"message": "Session token is invalid"}, "asym", user_public_key)
                return jsonify(res_encrypted), 401

            # delete user-server symetric key
            # delete session token from database
            #

        @self.app.route('/login', methods=['POST'])
        def login():
            user_public_key = request.get_json().get("user_public_key")
            data = self.encryption.decrypt_body(request, "asym", "request")
            username = data.get('username')
            password = data.get('password')
            print(password)
            self.db_manager.execute(
                'SELECT password, salt FROM users WHERE username=?', (username,))
            user = self.db_manager.fetchone()
            if user:
                stored_password, salt = user
                hashed_password, _ = self.encryption.hash_salt(password, salt)
                if hashed_password == stored_password:
                    # Generate a session token
                    session_token = str(uuid.uuid4())

                    self.db_manager.execute(
                        'UPDATE users SET session_token=?, session_token_date=? WHERE username=?', (session_token, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username))
                    self.db_conexion.commit()

                    user_id = self.db_manager.execute(
                        'SELECT id FROM users WHERE username=?', (username,)).fetchone()[0]

                    res_encrypted = self.encryption.get_encrypted_body(
                        {'message': 'Login successful', 'session_token': session_token, "user_id": user_id}, "asym", user_public_key)
                    return jsonify(res_encrypted), 200

            res_encrypted = self.encryption.get_encrypted_body(
                {'message': 'Invalid credentials'}, "asym", user_public_key)

            return jsonify(res_encrypted), 401

    # end cripto----


if __name__ == '__main__':
    chat_app = ChatApp()
    chat_app.run()
