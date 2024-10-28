import sqlite3
import uuid
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, join_room, leave_room, emit

from datetime import datetime, timedelta
from encryption import Encryption
from jsonManager import JsonManager


class ChatApp:
    def __init__(self):

        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app)
        # on initialization private and public keys are generated for asymetric encryption if they do not exists

        self.encryption = Encryption("SERVER")
        self.json_keys = JsonManager("json_keys.json")
        self.db_conexion = sqlite3.connect(
            "shachat.db", check_same_thread=False)
        self.db_manager = self.db_conexion.cursor()

        # check if tables exist

        self.db_manager.execute(
            '''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, salt TEXT, session_token TEXT, session_token_date TEXT, sym_key TEXT)''')
        self.db_conexion.commit()
        self.db_manager.execute('''
            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                origin_user_id INTEGER,
                receiver_user_id INTEGER,
                cypher_message TEXT,
                encoded_nonce TEXT,
                encoded_aad TEXT, 
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.db_conexion.commit()

        self.focused_chats = {}
        self.public_keys = {}
        self.connected_users = []
        self._create_restfull_routes()
        self._create_chat_routes()

    def run(self):
        self.socketio.run(self.app, host="localhost", port=5000, debug=True)

    def _create_restfull_routes(self):
        @self.app.route('/get-public-key', methods=['GET'])
        def getPublicKey():
            key = self.encryption.export_public_key()
            return jsonify({"public_key": key}), 200

        # this is used in the exchange_keys method on the client
        @self.app.route('/get-public-key-from-target-user/<string:dest_user_id>', methods=['GET'])
        def getPublicKeyFromTargetUser(dest_user_id):
            try:
                print(self.public_keys.keys())
                if dest_user_id in self.connected_users:
                    key = self.public_keys[dest_user_id]
                else:
                    raise Exception
                return jsonify({"public_key": key}), 200
            except Exception:
                return jsonify({"message": "User must be connected to initiate encripted chat"}), 400

        @self.app.route('/receive-client-keys', methods=['POST'])
        def receiveSymmetricKeyFromClient():
            public_key = request.get_json().get('public_key')
            data = self.encryption.decrypt_body(
                request, "asym", "request")
            username = data.get('username')
            user_id = data.get('user_id')
            sym_key = data.get('sym_key')
            self.public_keys[str(user_id)] = public_key

            # print(self.public_keys[str(user_id)])
            # print("THIS IS THE SYM KEY IN THE SERVER:", sym_key)
            # print("THIS IS THE ASYM KEY IN THE SERVER:", public_key)

            try:
                self.db_manager.execute('UPDATE users SET sym_key=? WHERE username=?', (
                    sym_key, username))
                self.db_conexion.commit()
                # sym key is stored on a json for quick access and on databse as well, might delete database storage later

                self.json_keys.add_entry(
                    str(user_id), self.encryption.encrypt_for_json_keys(sym_key))
                return jsonify({'message': 'Sym key received'}), 200
            except sqlite3.IntegrityError:
                return jsonify({'message': 'Error saving sym key'}), 409

        @self.app.route("/get-all-users-names/<string:user_id>", methods=["GET"])
        def getAllUserNames(user_id):
            try:
                result = self.db_manager.execute(
                    'SELECT id, username FROM users WHERE id != ?', (user_id,)).fetchall()

                # print("THIS IS THE KEY IN THE SERVER:",self.json_keys.search_entry(user_id))

                res = self.encryption.get_encrypted_body(
                    {"all_users": result}, "sym", self.encryption.asymmetric_decrypt(self.json_keys.search_entry(user_id)), "server")

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

                for i in self.connected_users:
                    self.socketio.emit('user_registered', {
                        'username': username
                    }, to=i)
                    print(i)
                print("USER REGISTERED")

                return jsonify({'message': 'Registration successful'}), 201
            except sqlite3.IntegrityError:
                return jsonify({'message': 'Username already exists'}), 409

        @self.app.route('/check-session-token', methods=['POST'])
        def checkSessionToken():
            # get token from the database
            user_public_key = request.get_json().get("user_public_key")
            data = self.encryption.decrypt_body(request, "asym", "request")
            session_token = data["session_token"]
            # print("USER PUBLIC KEY:", user_public_key)

            try:
                result = self.db_manager.execute('SELECT id,username,session_token_date FROM users WHERE session_token = ?', (
                    session_token,))
                result = self.db_manager.fetchone()
                print("result", result)
                # check the date and determine if it is valid
                if not result:
                    return jsonify({"message": "Invalid session token"}), 401

                user_id = result[0]
                username = result[1]
                session_token_date_string = result[2]

                session_token_date = datetime.strptime(
                    session_token_date_string, '%Y-%m-%d %H:%M:%S')

                current_time = datetime.now()
                token_expiration_date = session_token_date + \
                    timedelta(seconds=200000)

                if current_time > token_expiration_date:
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
            data = self.encryption.decrypt_body(request, "asym", "request")
            session_token = data.get('session_token')
            user_id = data.get('user_id')

            if (user_id):
                # delete symetric key
                self.json_keys.delete_entry(str(user_id))
            try:
                cursor = self.db_manager.execute(
                    'UPDATE users SET session_token=? WHERE session_token=?', (None, session_token))
                if cursor.rowcount == 0:
                    raise ValueError("Session token not found.")
                self.db_conexion.commit()

                return jsonify({"message": "Succesfully log out"}), 200

            except Exception as e:

                return jsonify({"message": "Session token is invalid"}), 401

            # delete user-server symetric key
            # delete session token from database
            #

        @self.app.route('/login', methods=['POST'])
        def login():
            user_public_key = request.get_json().get("user_public_key")
            data = self.encryption.decrypt_body(request, "asym", "request")
            username = data.get('username')
            password = data.get('password')
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

        @self.app.route('/get-conversation/<string:origin_user_id>/<string:receiver_user_id>', methods=['GET'])
        def get_conversation(origin_user_id, receiver_user_id):
            try:
                self.db_manager.execute('''
                    SELECT origin_user_id, receiver_user_id, cypher_message, timestamp,encoded_nonce,encoded_aad
                    FROM chats
                    WHERE (origin_user_id = ? AND receiver_user_id = ?)
                    OR (origin_user_id = ? AND receiver_user_id = ?)
                    ORDER BY timestamp ASC
                ''', (origin_user_id, receiver_user_id, receiver_user_id, origin_user_id))

                messages = self.db_manager.fetchall()

                conversation = []
                for msg in messages:
                    conversation.append({
                        'origin_user_id': msg[0],
                        'receiver_user_id': msg[1],
                        'message': {"cypher_message": msg[2], "encoded_nonce": msg[4], "encoded_aad": msg[5]},
                        'timestamp': msg[3]
                    })

                return jsonify({'conversation': conversation}), 200

            except sqlite3.Error as e:
                # print(f"Database error: {e}")
                return jsonify({'message': 'Error retrievin conversation'}), 500

    def _create_chat_routes(self):
        @self.socketio.on("connect")
        def handle_connection():
            user_id = request.args.get('user_id')

            print(f"{user_id} has connected {type(user_id)}")
            self.focused_chats[str(user_id)] = None
            if str(user_id) not in self.connected_users:
                self.connected_users.append(str(user_id))
            join_room(user_id)

        @self.socketio.on("disconnect")
        def handle_disconnection():
            user_id = request.args.get('user_id')
            print(f"{user_id} has disconnected")
            if str(user_id) in self.focused_chats:
                del self.focused_chats[str(user_id)]
            if str(user_id) in self.connected_users:
                self.connected_users.remove(str(user_id))
            leave_room(user_id)

        @self.socketio.on("exchange_keys")
        def handle_exchange_keys(data):
            print("HANDLING EXCHANGE KEYS")
            user_id = str(data['user_id'])
            cypher_sym_key = data['cypher_sym_key']
            receiver_id = str(data['dest_user_id'])
            emit('send_private_key', {'origin_user_id': user_id,
                                      'cypher_sym_key': cypher_sym_key}, room=receiver_id)

        @self.socketio.on("message_sent")
        def handle_sent_message(data):
            receiver_id = str(data['receiver_id'])
            message = data['message']
            origin_user_id = str(data['origin_user_id'])
            origin_user_name = data['origin_user_name']

            print(
                f"Message receive from {origin_user_name} to {receiver_id}")
            # Emit the message to the recipient's room
            print("receiver_id:" + receiver_id, " ", type(receiver_id))

            if receiver_id in self.focused_chats and self.focused_chats[receiver_id] == origin_user_id:
                emit('receive_message', {'origin_user_id': origin_user_id, "origin_user_name": origin_user_name,
                                         'message': message}, room=receiver_id)

            self.db_manager.execute('''
                INSERT INTO chats (origin_user_id, receiver_user_id, cypher_message, encoded_nonce, encoded_aad)
                VALUES (?, ?, ?,?,?)
            ''', (origin_user_id, receiver_id, message["cypher_message"], message["encoded_nonce"], message["encoded_aad"]))
            self.db_conexion.commit()
            # save on database

            # TODO: we could notify

        @self.socketio.on("update_focused_chat")
        def handle_update_focused_chat(data):
            current_chat_id = str(data['current_chat_id'])
            user_id = str(data['user_id'])
            print(f"focus chat of {user_id} is {current_chat_id}")

            self.focused_chats[str(user_id)] = str(current_chat_id)


if __name__ == '__main__':
    chat_app = ChatApp()
    chat_app.run()
