import sqlite3
import uuid
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, send
import os
import base64
from cryptography.hazmat.primitives import hashes


class ChatApp:
    def __init__(self):

        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app)

        self.db_conexion = sqlite3.connect(
            "shachat.db", check_same_thread=False)
        self.db_manager = self.db_conexion.cursor()

        # check if tables exist

        self.db_manager.execute(
            '''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, salt TEXT, session_token TEXT)''')
        self.db_conexion.commit()

        self._create_restfull_routes()

    def run(self):
        self.socketio.run(self.app, host="localhost", port=5000, debug=True)

    # cripto----
    def _create_restfull_routes(self):
        @self.app.route('/register', methods=['POST'])
        def register():
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            hashed_password, salt = self.hash_salt(password, None)

            try:
                self.db_manager.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)', (
                    username, hashed_password, salt))
                self.db_conexion.commit()
                return jsonify({'message': 'Registration successful'}), 201
            except sqlite3.IntegrityError:
                return jsonify({'message': 'Username already exists'}), 409

        @self.app.route('/login', methods=['POST'])
        def login():
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            self.db_manager.execute(
                'SELECT password, salt FROM users WHERE username=?', (username,))
            user = self.db_manager.fetchone()
            if user:
                stored_password, salt = user
                hashed_password, _ = self.hash_salt(password, salt)
                if hashed_password == stored_password:
                    # Generate a session token
                    session_token = str(uuid.uuid4())
                    self.db_manager.execute(
                        'UPDATE users SET session_token=? WHERE username=?', (session_token, username))
                    self.db_conexion.commit()
                    return jsonify({'message': 'Login successful', 'session_token': session_token}), 200

            return jsonify({'message': 'Invalid credentials'}), 401

    def hash_salt(self, password, salt):
        print(type(salt))
        if salt is None:
            salt = os.urandom(32)
        else:
            salt = base64.b64decode(salt)
        salt_base64 = base64.b64encode(salt).decode('utf-8')
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode('utf-8'))
        digest.update(salt)
        password_hashed = digest.finalize()
        password_hashed_base64 = base64.b64encode(
            password_hashed).decode('utf-8')

        return password_hashed_base64, salt_base64
    # end cripto----


if __name__ == '__main__':
    chat_app = ChatApp()
    chat_app.run()
