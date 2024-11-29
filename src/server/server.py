import sqlite3
import uuid
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, join_room, leave_room, emit
import base64
from datetime import datetime, timedelta
from encryption import Encryption
from jsonManager import JsonManager


class ChatApp:
    def __init__(self):
        # Crea una instancia de la app Flask
        self.app = Flask(__name__)
        # Inicializamos Socket
        self.socketio = SocketIO(self.app)
        # on initialization private and public keys are generated for asymetric encryption if they do not exists
        # Al inicializar las claves públicas y las privadas asimétricas son generadas si no existen

        self.encryption = Encryption("SERVER")
        self.json_keys = JsonManager("json_keys.json")

        server_password = input("introduce server password:\n")
        self.encryption.generate_logged_asymetric(server_password, "server")

        # Establecemos conexión con la base de datos
        self.db_conexion = sqlite3.connect(
            "shachat.db", check_same_thread=False)
        self.db_manager = self.db_conexion.cursor()

        # Chequea la tabla y si no existe la crea

        self.db_manager.execute(
            '''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            salt TEXT,
            session_token TEXT,
            session_token_date TEXT,
            certificate TEXT
            )
        ''')

        self.db_conexion.commit()

        self.db_manager.execute('''
            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                origin_user_id INTEGER,
                receiver_user_id INTEGER,
                cypher_message TEXT,
                encoded_nonce TEXT,
                encoded_aad TEXT,
                signature TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.db_conexion.commit()

        # Diccionarios para almacenar en que chat está enfocado cada usuario, para almacenar las claves públicas de los usuarios conectados y los
        # usuarios conectados respectivamente.
        self.focused_chats = {}
        self.public_keys = {}
        self.connected_users = []

        # LLama al método que crea las rutas de la API Restful
        self._create_restfull_routes()

        # LLama al método que crea las rutas de  WebSockets.
        self._create_chat_routes()

    # Inicia el servidor Flask y habilita el soporte de WebSockets usando SocketIO
    def run(self):
        self.socketio.run(self.app, host="localhost", port=44444, debug=False)

    def _create_restfull_routes(self):
        @self.app.route('/get-public-key', methods=['GET'])
        # Método para obtener la clave pública del servidor
        def getPublicKey():
            key = self.encryption.export_public_key()
            return jsonify({"public_key": key}), 200

        # Esto es usada en el método de intercambio de claves en el cliente
        @self.app.route('/get-public-key-from-target-user/<string:dest_user_id>', methods=['GET'])
        def getPublicKeyFromTargetUser(dest_user_id):
            # Intenta obtener la clave pública del usuario de destino y la devuelve en formato json si existe junto al código 200 (éxito)
            try:
                print(self.public_keys.keys())
                if dest_user_id in self.connected_users:
                    print("hii", dest_user_id, self.connected_users)
                    key = self.public_keys[dest_user_id]
                else:
                    raise Exception
                return jsonify({"public_key": key}), 200
            # Si no la obtiene devuelve una excepción
            except Exception:
                return jsonify({"message": "User must be connected to initiate encripted chat"}), 400

        @self.app.route('/get-certificate-from-target-user/<string:dest_user_id>/<string:exchanging>', methods=['GET'])
        def getCertificateFromUser(dest_user_id, exchanging):
            try:
                if exchanging == "0" and dest_user_id not in self.connected_users:
                    raise Exception("User not connected")
                result = self.db_manager.execute(
                    'SELECT certificate FROM users WHERE id = ?', (
                        dest_user_id,)
                ).fetchone()

                # check if the dest_user_id is connected, if not, raise exception

                if result:
                    certificate = result[0]

                else:
                    raise Exception
                return jsonify({"certificate": certificate}), 200
            # Si no la obtiene devuelve una excepción
            except Exception:
                return jsonify({"message": "User must be connected to initiate encripted chat"}), 400

        @self.app.route('/save_certificate', methods=['POST'])
        def saveCertificate():
            try:
                certificate = request.get_json().get("certificate")
                user_id = request.get_json().get("user_id")

                self.db_manager.execute('UPDATE users SET certificate = ? WHERE id = ?', (
                    certificate, user_id))
                self.db_conexion.commit()

                print("CERTIFICADO GUARDADO EN BBDD!")
                return jsonify({'message': 'Cerificate saved succesfull'}), 201
            except Exception as e:
                print(e)
                return jsonify({'message': f'Error in sql:{e}'}), 409

        @self.app.route('/receive-client-keys', methods=['POST'])
        # Permite que un cliente envie su clave simétrica al server
        def receiveSymmetricKeyFromClient():
            # Se extrae la clave del cuerpo de la solicitud en formato json
            public_key = request.get_json().get('public_key')
            # Se desencripta el cuerpo de la solicitud y lo almacenamos en data, posteriormente extraemos los fragmentos de data
            data = self.encryption.decrypt_body(
                request, "asym", "request")
            username = data.get('username')
            user_id = data.get('user_id')
            sym_key = data.get('sym_key')
            # La clave pública del cliente se almacena en el diccionario public_keys del servidor, utilizando el user_id como clave.
            self.public_keys[str(user_id)] = public_key

            # print(self.public_keys[str(user_id)])
            # print("THIS IS THE SYM KEY IN THE SERVER:", sym_key)
            # print("THIS IS THE ASYM KEY IN THE SERVER:", public_key)

            # Intentamos actualizar la tabla users en la base de datos, guardando la clave simétrica del cliente asociado al nombre de usuario.
            try:
                # self.db_manager.execute('UPDATE users SET sym_key=? WHERE username=?', (
                #     sym_key, username))
                # self.db_conexion.commit()
                # La clave simétrica se almacena en un archivo JSON para un acceso rápido y también en la base de datos
                # es posible que se elimine el almacenamiento en la base de datos más adelante.

                self.json_keys.add_entry(
                    str(user_id), self.encryption.encrypt_for_json_keys(sym_key))
                return jsonify({'message': 'Sym key received'}), 200
            except sqlite3.IntegrityError:
                return jsonify({'message': 'Error saving sym key'}), 409

        @self.app.route("/get-all-users-names/<string:user_id>", methods=["GET"])
        def getAllUserNames(user_id):
            try:
                # En result almacenamos una tupla con todos los nombres de los usuarios distintos de user_id, asociados a su respectivo id
                result = self.db_manager.execute(
                    'SELECT id, username FROM users WHERE id != ?', (user_id,)).fetchall()

                # print("THIS IS THE KEY IN THE SERVER:",self.json_keys.search_entry(user_id))

                # Encriptamos result con la clave simétrica
                res = self.encryption.get_encrypted_body(
                    {"all_users": result}, "sym", self.encryption.asymmetric_decrypt(self.json_keys.search_entry(user_id)), "server")

                # Devolvemos la respuesta en formato json y el código de éxito en la operación
                return jsonify(res), 200

            # Si hay algún error de sql, lanzamos excepción
            except sqlite3.Error:
                jsonify({'message': 'Error in the database'}), 401

        @self.app.route('/register', methods=['POST'])
        # Método que gestiona el registro de nuevos usuarios
        def register():
            # Se decripta el cuerpo de la solicitud y se almacena en data, posteriormente se sacan los datos del cuerpo
            data = self.encryption.decrypt_body(request, "asym", "request")
            username = data.get('username')
            password = data.get('password')
            hashed_password, salt = self.encryption.hash_salt(password, None)

            # Tratamos de almacenar los datos en la base de datos
            try:
                self.db_manager.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)', (
                    username, hashed_password, salt))
                self.db_conexion.commit()

                # Se notifica a los usuarios conectados el nuevo registro
                for i in self.connected_users:
                    self.socketio.emit('user_registered', {
                        'username': username
                    }, to=i)
                    print(i)
                print("USER REGISTERED")

            # En función del exito de la operación imprimimos un mensaje u otro y su status
                return jsonify({'message': 'Registration successful'}), 201
            except sqlite3.IntegrityError:
                return jsonify({'message': 'Username already exists'}), 409

        @self.app.route('/check-session-token', methods=['POST'])
        # Método para verificar si el session token es válido
        def checkSessionToken():
            # Se extrae la clave pública del cliente del cuerpo de la solicitud, que se envía en formato JSON
            user_public_key = request.get_json().get("user_public_key")
            # El servidor desencripta el cuerpo de la solicitud que contiene el token de sesión, utilizando la encriptación asimétrica
            data = self.encryption.decrypt_body(request, "asym", "request")
            # Se extrae el token
            session_token = data["session_token"]
            # print("USER PUBLIC KEY:", user_public_key)

            # Se intenta buscar el session_token en la base de datos para verificar si es válido
            try:
                result = self.db_manager.execute('SELECT id,username,session_token_date FROM users WHERE session_token = ?', (
                    session_token,))
                # Se almacena en result la primera fila que coincide con la consulta
                result = self.db_manager.fetchone()
                print("result", result)
                # Verifica la fecha y determina si es válida
                if not result:
                    return jsonify({"message": "Invalid session token"}), 401

                # data de la data base
                user_id = result[0]
                username = result[1]
                session_token_date_string = result[2]

                # convierte la fecha de la cadena a un objeto de tipo datetime
                session_token_date = datetime.strptime(
                    session_token_date_string, '%Y-%m-%d %H:%M:%S')

                # calculo de fecha actual y fecha de expiración
                current_time = datetime.now()
                token_expiration_date = session_token_date + \
                    timedelta(seconds=200000)

                # se comproeba si el token sigue vigente

                if current_time > token_expiration_date:
                    res_encrypted = self.encryption.get_encrypted_body(
                        {"message": "Session token is expired, ohhh :("}, "asym", user_public_key)
                    return jsonify(res_encrypted), 401
                # Token es valido

                res_encrypted = self.encryption.get_encrypted_body(
                    {"message": "Session token is valid, lets goooo", "user_id": user_id, "username": username}, "asym", user_public_key)
                return jsonify(res_encrypted), 200

            except sqlite3.Error as e:  # Manejo de excepciones
                print(f"Database error: {e}")
                res_encrypted = self.encryption.get_encrypted_body(
                    {"message": "Invalid session token"}, "asym", user_public_key)
                return jsonify(res_encrypted), 401

                # return jsonify({}), 200

        @self.app.route('/logout', methods=['POST'])
        # Método para gestionar el logout
        def logout():
            data = self.encryption.decrypt_body(request, "asym", "request")
            session_token = data.get('session_token')
            user_id = data.get('user_id')

            if (user_id):
                # Borramos symetric key
                self.json_keys.delete_entry(str(user_id))
            try:
                cursor = self.db_manager.execute(
                    'UPDATE users SET session_token=? WHERE session_token=?', (None, session_token))
                if cursor.rowcount == 0:
                    raise ValueError("Session token not found.")
                self.db_conexion.commit()

                return jsonify({"message": "Succesfully log out"}), 200

            # Manejo de errores
            except Exception as e:

                return jsonify({"message": "Session token is invalid"}), 401

        @self.app.route('/login', methods=['POST'])
        def login():
            # Obtenemos la clave pública del usuario del cuerpo de la solicitud
            user_public_key = request.get_json().get("user_public_key")
            # Desencriptamos el cuerpo de la solicitud y sacamos los datos
            data = self.encryption.decrypt_body(request, "asym", "request")
            username = data.get('username')
            password = data.get('password')
            # Obtenemos el salt y la contraseña del usuario y lo guardamos en user
            self.db_manager.execute(
                'SELECT password, salt FROM users WHERE username=?', (username,))
            user = self.db_manager.fetchone()
            # Si el usuario es encontrado se extrae la contraseña almacenada y el salt
            if user:
                stored_password, salt = user
                # Se vuelve a calcular el hash de la contraseña proporcionada por el usuario usando la misma sal, para poder compararlo con el hash almacenado.
                hashed_password, _ = self.encryption.hash_salt(password, salt)
                if hashed_password == stored_password:
                    # Generamos un session token
                    session_token = str(uuid.uuid4())

                    # Actualizamos el session token en la bb dd
                    self.db_manager.execute(
                        'UPDATE users SET session_token=?, session_token_date=? WHERE username=?', (session_token, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username))
                    self.db_conexion.commit()

                    # Obtenemos el id de usuario
                    user_id = self.db_manager.execute(
                        'SELECT id FROM users WHERE username=?', (username,)).fetchone()[0]

                    # Ciframos la respuesta y la devolvemos en formato json
                    res_encrypted = self.encryption.get_encrypted_body(
                        {'message': 'Login successful', 'session_token': session_token, "user_id": user_id}, "asym", user_public_key)
                    return jsonify(res_encrypted), 200

            # Caso de logeo incorrecto por contraseña o usuario no válido
            res_encrypted = self.encryption.get_encrypted_body(
                {'message': 'Invalid credentials'}, "asym", user_public_key)

            return jsonify(res_encrypted), 401

        @self.app.route('/get-conversation/<string:origin_user_id>/<string:receiver_user_id>', methods=['GET'])
        # Método para recuperar el historial de mensajes cifrados entre dos usuarios y devolverlo en formato json
        def get_conversation(origin_user_id, receiver_user_id):
            # Consulta sql para recuperar todos los mensajes entre los dos usuarios y los ordena por timestamp
            try:
                self.db_manager.execute('''
                    SELECT origin_user_id, receiver_user_id, cypher_message, timestamp,encoded_nonce,encoded_aad,signature
                    FROM chats
                    WHERE (origin_user_id = ? AND receiver_user_id = ?)
                    OR (origin_user_id = ? AND receiver_user_id = ?)
                    ORDER BY timestamp ASC
                ''', (origin_user_id, receiver_user_id, receiver_user_id, origin_user_id))

                # Almacena todos los mensajes en messages que es una tupla con los datos de la conversación
                messages = self.db_manager.fetchall()

                # Cada tupla se agrega a la lista conversation, que al final contendrá toda la conversación entre los dos usuarios en el formato adecuado.
                conversation = []
                for msg in messages:
                    conversation.append({
                        'origin_user_id': msg[0],
                        'receiver_user_id': msg[1],
                        'message': {"cypher_message": msg[2], "encoded_nonce": msg[4], "encoded_aad": msg[5]},
                        'timestamp': msg[3],
                        'signature': base64.b64encode(
                            msg[6]).decode('utf-8')
                    })

                print(conversation)

                # Devolvemos conversation en formato json y el status de éxito.
                return jsonify({'conversation': conversation}), 200

            except sqlite3.Error as e:
                # print(f"Database error: {e}")
                return jsonify({'message': 'Error retrievin conversation'}), 500

    # Método que se encarga de crear las rutas y la lógica de los WebSockets
    def _create_chat_routes(self):
        @self.socketio.on("connect")
        # Función que se encarga de manejar lo que sucede cuando un cliente se conecta
        def handle_connection():
            # El ID del usuario se obtiene de los parámetros de la URL que se envían cuando el cliente se conecta al servidor
            user_id = request.args.get('user_id')

            print(f"{user_id} has connected {type(user_id)}")
            # En este caso indicamos que el usuario no está activo dentro de ningún chat actualmente
            self.focused_chats[str(user_id)] = None
            # Si el usuario no aparece como usuario conectado (que es lo lógico pues se acaba de conectar), lo añadimos a la lista
            if str(user_id) not in self.connected_users:
                self.connected_users.append(str(user_id))
            # Asignamos al usuario una sala con su id
            join_room(user_id)

        @self.socketio.on("disconnect")
        # Maneja lo que sucede cuando el usuario se desconecta
        def handle_disconnection():
            # Obtiene el id que fue enviado como parámetro
            user_id = request.args.get('user_id')
            print(f"{user_id} has disconnected")
            # Eliminamos el focused_chat del usuario del diccionario
            if str(user_id) in self.focused_chats:
                del self.focused_chats[str(user_id)]
            # Eliminamos al usuario del diccionario de clientes activos
            if str(user_id) in self.connected_users:
                self.connected_users.remove(str(user_id))
            # Lo sacamos de la sala en la que se encontraba
            leave_room(user_id)

        @self.socketio.on("exchange_keys")
        # Método para intercambiar claves simétricas a través del socket
        def handle_exchange_keys(data):
            print("HANDLING EXCHANGE KEYS")
            # Extraemos de data (es un diccionario) los datos de los distintos campos
            user_id = str(data['user_id'])
            cypher_sym_key = data['cypher_sym_key']
            receiver_id = str(data['dest_user_id'])
            # El server va a emitir a través de un socket el envio de la clave simétrica cifrada al cliente de destino
            emit('send_private_key', {'origin_user_id': user_id,
                                      'cypher_sym_key': cypher_sym_key}, room=receiver_id)

        @self.socketio.on("message_sent")
        # Método que se encarga de recibir el mensaje cifrado, almacenarlo en la bb. ddd. y reenviarlo al destinatario si está disponible
        def handle_sent_message(data):
            # Extraemos los datos de data y los almacenamos en variables
            receiver_id = str(data['receiver_id'])
            message = data['message']
            origin_user_id = str(data['origin_user_id'])
            origin_user_name = data['origin_user_name']
            signature = data['signature']

            print(
                f"Message receive from {origin_user_name} to {receiver_id}")
            # Emite el mensaje a la sala del destinatario
            print("receiver_id:" + receiver_id, " ", type(receiver_id))

            # Verifica si el usuario receptor está activo en un chat y comprueba si este chat es el del emisor
            if receiver_id in self.focused_chats and self.focused_chats[receiver_id] == origin_user_id:
                # Si se da la condición emitimos el envio del mensaje al receptor
                emit('receive_message', {'origin_user_id': origin_user_id, "origin_user_name": origin_user_name,
                                         'message': message, "signature": signature}, room=receiver_id,)

            # Guarda mensaje en la base de datos
            self.db_manager.execute('''
                INSERT INTO chats (origin_user_id, receiver_user_id, cypher_message, encoded_nonce, encoded_aad, signature)
                VALUES (?, ?, ?,?,?,?)
            ''', (origin_user_id, receiver_id, message["cypher_message"], message["encoded_nonce"], message["encoded_aad"], data["signature"]))
            self.db_conexion.commit()

            # TODO: we could notify

        @self.socketio.on("update_focused_chat")
        # Método que se encarga de actualizar el chat en el que está activo el usuario actualmente.
        def handle_update_focused_chat(data):
            # Extraemos el id del usuario y el id del chat con el que el usuario está enfocando actualmente.
            current_chat_id = str(data['current_chat_id'])
            user_id = str(data['user_id'])
            print(f"focus chat of {user_id} is {current_chat_id}")

            # Actualizamos el diccionario que indica en que chat está activo el usuario
            self.focused_chats[str(user_id)] = str(current_chat_id)


if __name__ == '__main__':
    chat_app = ChatApp()
    chat_app.run()
