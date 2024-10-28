import tkinter as tk
from tkinter import messagebox
from jsonManager import JsonManager
import requests
from encryption import Encryption
import json
from tkinter import ttk
import time
import os
import threading
import socketio
from collections import deque
from tkinter.simpledialog import askstring


SERVER = "http://localhost:5000"


class AppLogic:
    def __init__(self):
        self.session_token = None
        self.username = None
        self.user_id = None
        self.json_keys = None
        self.encryption = Encryption()
        self.server_public_key = None
        self.socket = None
        self.new_registration = False
        self._getServerPublicKey()

        # this is the message queue to update the UI chat
        self.message_queue = deque()

    def _getServerPublicKey(self):
        response = requests.get(
            f"{SERVER}/get-public-key")

        if response.status_code == 200:
            self.server_public_key = response.json().get("public_key")
            # print("SERVER PUBLIC KEY:", self.server_public_key)

        else:
            print("unable to get public key")

    def connect_to_socket(self):

        self.socket = socketio.Client()

        @self.socket.event
        def connect():
            print("Socket has been connected")
            # sendKeys?

        @self.socket.event
        def disconnect():
            print("Socket disconnected")

        @self.socket.on("user_registered")
        def on_user_registered(data):
            print("OTHER USER REGISTERED")
            if self.user_id != None:
                self.new_registration = True

        @self.socket.on("receive_message")
        def on_message(data):

            decrypted_message = self.encryption.decrypt_body(
                data["message"], "sym", "json", self.encryption.asymmetric_decrypt(self.json_keys.search_entry(str(data["origin_user_id"]))))

            self.message_queue.append({'origin_user_id': data['origin_user_id'], "origin_user_name": data['origin_user_name'],
                                       'message': decrypted_message})

        @self.socket.on("send_private_key")
        def on_send_private_key(data):
            print(f"Received private_key")

            sym_key = self.encryption.asymmetric_decrypt(
                data["cypher_sym_key"])

            self.json_keys.add_entry(
                data["origin_user_id"], self.encryption.encrypt_for_json_keys(sym_key))

        try:

            self.socket.connect(
                f"{SERVER}?user_id={self.user_id}")
        except Exception as e:
            print("Unable to connect to the socket:", e)

    def getOrExchangeSymKeysEndToEnd(self, dest_user_id):

        val = self.json_keys.search_entry(str(dest_user_id))
        if val:
            print("EXCHANGE WAS ALREADY PRODUCED")
            return self.encryption.asymmetric_decrypt(val)

        response = requests.get(
            f"{SERVER}/get-public-key-from-target-user/{dest_user_id}")

        dest_user_public_key = response.json().get("public_key")

        if response.status_code == 400:
            return False

        sym_key = self.encryption.generate_symetric_key()
        self.json_keys.add_entry(
            str(dest_user_id), self.encryption.encrypt_for_json_keys(sym_key))
        # body = {"origin_user_id": origin_user_id, "sym_key": sym_key}
        # get other user public key

        print("PUBLIC KEY RECEIVED FROM DEST USER")
        cypher_sym_key = self.encryption.asymmetric_encrypt_with_external_public_key(
            dest_user_public_key, sym_key)

        print("SOCKET EMMITED")

        self.socket.emit('exchange_keys', {
            "user_id": self.user_id, "dest_user_id": dest_user_id, "cypher_sym_key": cypher_sym_key})

        return sym_key

    def getAllUsers(self):
        response = requests.get(
            f"{SERVER}/get-all-users-names/{self.user_id}")

        if response.status_code == 200:
            response_body = self.encryption.decrypt_body(
                response, "sym", "response", self.encryption.asymmetric_decrypt(self.json_keys.search_entry("server")))
            return response_body.get("all_users")
        else:
            print("unable to get all users")

    def send_message_via_socket(self, receiver_id, message):
        print("MENSAJE ENVIADO")
        # encript message
        encrypted_message = self.encryption.get_encrypted_body(
            message, "sym", self.encryption.asymmetric_decrypt(self.json_keys.search_entry(str(receiver_id))), str(self.user_id))

        if self.socket:
            self.socket.emit('message_sent', {
                             "origin_user_id": self.user_id, "origin_user_name": self.username, 'receiver_id': receiver_id, "message": encrypted_message})

    def update_focused_chat(self, current_chat_id):
        self.socket.emit('update_focused_chat', {
            "user_id": self.user_id, "current_chat_id": current_chat_id})

    def get_message_from_queue(self, current_chat_user_id):
        try:
            if str(self.message_queue[0]["origin_user_id"]) != str(current_chat_user_id):
                return None
            else:
                message_data = self.message_queue.popleft()
            return message_data
        except Exception as e:
            # print(e)
            return None

    def get_conversation(self, other_user_id):
        try:
            response = requests.get(
                f"{SERVER}/get-conversation/{self.user_id}/{other_user_id}")

            if response.status_code == 200:
                response_body = response.json()
                return response_body.get("conversation")
            else:
                print(f"Could not fetch conversations")
                return []
        except Exception as e:
            print(f"Error fetching conversation: {e}")
            return []

    def checkSessionToken(self, display_login, display_chat, log_out, ask_password):
        print("CHECKING TOKEN...")
        try:
            with open("session_token.json", "r") as session_token_file:
                data = json.load(session_token_file)

            session_token = data["session_token"]
            body = {"session_token": session_token}
            body_encrypted = self.encryption.get_encrypted_body(
                body, "asym", self.server_public_key)
            body_encrypted["user_public_key"] = self.encryption.export_public_key(
            )

            response = requests.post(
                f"{SERVER}/check-session-token", json=body_encrypted)

            response_body = self.encryption.decrypt_body(
                response, "asym", "response")

            # print(response_body.get('message'))
            self.username = response_body.get("username")
            self.user_id = response_body.get("user_id")
            if response.status_code == 200:
                self.json_keys = JsonManager(f"json_keys_{self.user_id}.json")

                password = ask_password()
                if not password:
                    log_out(True)
                    return

                try:
                    self.sendClientKeysToServer(password, self.user_id)
                    print("sibueno")

                except Exception as e:
                    print("nobueno:", "-", e)
                    log_out(True)
                    return

                self.session_token = session_token
                print("session is valid")
                self.encryption.owner = self.username
                threading.Thread(target=self.connect_to_socket).start()

                display_chat()

            else:
                print("session token has expired")
                log_out(True)
                return

        except FileNotFoundError:
            print("no session token file")
            display_login()
            return

    def sendClientKeysToServer(self, password, user_id):
        # TODO: ENCRYPT USING ASSYMETRIC

        # Generate new public and private key using user password

        key = self.encryption.generate_symetric_key()
        print("THIS IS THE KEY IN THE CLIENT:", key)

        self.encryption.generate_logged_asymetric(password, user_id)
        public_key = self.encryption.export_public_key(
        )
        body = {"username": self.username,
                "sym_key": key, "user_id": self.user_id}

        body_encrypted = self.encryption.get_encrypted_body(
            body, "asym", self.server_public_key)
        body_encrypted["public_key"] = public_key

        response = requests.post(
            f"{SERVER}/receive-client-keys", json=body_encrypted)

        if response.status_code == 200:
            self.json_keys.add_entry(
                "server", self.encryption.encrypt_for_json_keys(key))
        return [response.status_code, response.json().get('message')]

    def logout(self):
        body = {"session_token": self.session_token, "user_id": self.user_id}
        body_encrypted = self.encryption.get_encrypted_body(
            body, "asym", self.server_public_key)

        # TODO: ENCRYPT USING ASSYMETRIC
        requests.post(
            f"{SERVER}/logout", json=body_encrypted)

        # delete server sym
        if self.json_keys != None:
            self.json_keys.delete_entry("server")
        # delete own asym keys

        # TODO:REGENERATE
        self.encryption.generate_asym_keys()

        # self.encryption.regenerate_keys_asym()

        # set everything to nonw
        self.session_token = None
        self.username = None
        self.user_id = None
        self.json_keys = None

        if os.path.exists("session_token.json"):
            os.remove("session_token.json")

    def login(self, username, password):
        if not username or not password:
            return {"status": 0, "message": "you must cover all the inputs"}

        body = {"username": username, "password": password}
        body_encrypted = self.encryption.get_encrypted_body(
            body, "asym", self.server_public_key)

        body_encrypted["user_public_key"] = self.encryption.export_public_key(
        )

        # TODO: ENCRYPT USING ASSYMETRIC
        response = requests.post(
            f"{SERVER}/login", json=body_encrypted)

        response_body = self.encryption.decrypt_body(
            response, "asym", "response")

        if response.status_code == 200:
            self.username = username
            self.user_id = response_body.get('user_id')
            self.session_token = response_body.get('session_token')
            print(
                f'username: {self.username} with user_id {self.user_id} has just logged in')

            self.encryption.owner = self.username
            with open("session_token.json", "w") as session_token_file:
                json.dump({"session_token": self.session_token},
                          session_token_file)
            self.json_keys = JsonManager(f"json_keys_{self.user_id}.json")
            result = self.sendClientKeysToServer(password, self.user_id)
            threading.Thread(target=self.connect_to_socket).start()
            if result[0] != 200:
                return {"status": 0, "message": result[1]}
            return {"status": 1, "message": response_body.get('message')}
        else:
            return {"status": 0, "message": response_body.get('message')}

    def register(self, username, password, repeat_password):
        if not username or not password or not repeat_password:
            return {"status": 0, "message": "you must cover all the inputs"}

        if password != repeat_password:
            return {"status": 0, "message": "passwords do not match"}

        body = {"username": username, "password": password}
        # TODO: ENCRYPT USING ASSYMETRIC

        response = requests.post(
            f"{SERVER}/register", json=self.encryption.get_encrypted_body(body, "asym", self.server_public_key))

        if response.status_code == 201:
            return {"status": 1, "message": response.json().get('message')}
        else:
            return {"status": 0, "message": response.json().get('message')}


class UI:
    def __init__(self, root):
        self.root = root
        self.app_logic = AppLogic()
        self.root.title("SHAchat, secure chatting for free")
        self.root.geometry("1200x600")
        self.current_chat_user_id = None
        self.current_chat_user_name = None

        self.app_logic.checkSessionToken(
            self.display_login, self.display_chat, self.log_out, self.ask_for_password)

        self.check_for_messages()
        self.check_for_new_registrations()

    def check_for_messages(self):
        if self.current_chat_user_id != None:
            message_data = self.app_logic.get_message_from_queue(
                self.current_chat_user_id)
            if message_data:
                origin_user_id = message_data['origin_user_id']
                message = message_data['message']
                origin_user_name = message_data['origin_user_name']
                print(f"Got a message from {origin_user_name}: {message}")
                self.display_message(origin_user_name, message, "other")

        # Call every 500ms
        self.root.after(500, self.check_for_messages)

    def check_for_new_registrations(self):
        if self.app_logic.new_registration == True:
            print("Updating ui")
            self.app_logic.new_registration = False
            self.clear_screen()
            self.display_chat()

            if self.current_chat_user_id != None:
                self.load_chat(self.current_chat_user_id,
                               self.current_chat_user_name)

        self.root.after(1000, self.check_for_new_registrations)

    def ask_for_password(self):
        password = askstring("Password Required", "Enter your password:",
                             show='*')
        if password is None:
            return ""
        return password

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def display_loading(self):
        self.clear_screen()

        loading_frame = tk.Frame(self.root, bg="white")
        loading_frame.pack(fill=tk.BOTH, expand=True)

        loading_label = tk.Label(
            loading_frame, text="Loading, please wait...", font=("Verdana", 16), bg="white")
        loading_label.pack(pady=20)

        progress = ttk.Progressbar(loading_frame, mode='indeterminate')
        progress.pack(pady=20, padx=20)
        progress.start()

    def display_login(self):
        self.clear_screen()

        tk.Label(self.root, text="Login", font=("Verdana", 20)).pack(pady=12)

        tk.Label(self.root, text="Username").pack()
        self.username_val = tk.Entry(self.root)
        self.username_val.pack(pady=4)

        tk.Label(self.root, text="Password").pack()
        self.password_val = tk.Entry(self.root, show="*")
        self.password_val.pack(pady=4)

        tk.Button(self.root, text="Login",
                  command=self.login).pack(pady=12)
        tk.Button(self.root, text="Register",
                  command=self.display_register).pack()

    def display_register(self):
        self.clear_screen()

        tk.Label(self.root, text="Register",
                 font=("Verdana", 20)).pack(pady=12)

        tk.Label(self.root, text="Username").pack()
        self.username_val = tk.Entry(self.root)
        self.username_val.pack(pady=4)

        tk.Label(self.root, text="Password").pack()
        self.password_val = tk.Entry(self.root, show="*")
        self.password_val.pack(pady=4)

        tk.Label(self.root, text="Repeat password").pack()
        self.repeat_password_val = tk.Entry(self.root, show="*")
        self.repeat_password_val.pack(pady=4)

        tk.Button(self.root, text="Register",
                  command=self.register).pack(pady=12)
        tk.Button(self.root, text="Login",
                  command=self.display_login).pack(pady=12)

    def display_chat(self):
        self.clear_screen()
        self.user_list_frame = tk.Frame(
            self.root, bg="lightgray")
        self.user_list_frame.pack(
            side=tk.LEFT, fill=tk.Y, expand=False)

        # load users from database
        self.users = self.app_logic.getAllUsers()
        # ["Alice", "Bob", "Charlie charlie charlie", "Dave"]

        self.user_buttons = []

        tk.Label(self.user_list_frame, text=f"Available users",
                 bg="lightgray", font=("Vedana", 9, "bold")).pack(pady=10, padx=3)

        for user in self.users:
            # user[0] is the id and user[1] is the name
            button = tk.Button(self.user_list_frame, text=user[1],
                               command=lambda u=user: self.load_chat(u[0], u[1]))
            button.pack(fill=tk.X, pady=0, padx=20)

            # TODO:This can be used to change their colors later
            # self.user_buttons.append(button)

        # Chat display frame
        self.chat_display_frame = tk.Frame(self.root, bg="white")

        self.chat_display_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.header_frame = tk.Frame(self.chat_display_frame, bg="white")
        self.header_frame.pack(fill=tk.X, padx=10, pady=5)

        self.chat_label = tk.Label(
            self.header_frame, text=f"Hi {self.app_logic.username}! Select a user to start chatting", bg="white", font=("Vedana", 14, "bold"))
        # Add padding to separate the label from the button
        self.chat_label.pack(side=tk.LEFT, padx=(10, 10))

        self.log_out_button = tk.Button(
            self.header_frame, text="Log out", command=self.log_out)
        self.log_out_button.pack(side=tk.RIGHT, padx=20, pady=10)

        self.chat_text = tk.Text(
            self.chat_display_frame, state=tk.DISABLED, wrap=tk.WORD, relief="solid", bd=1)
        self.chat_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Message entry frame
        self.message_frame = tk.Frame(self.chat_display_frame, bg="white")
        self.message_frame.pack(fill=tk.X, padx=10, pady=7)

        self.message_entry = tk.Text(
            self.message_frame, relief="solid", bd=1, height=3)
        self.message_entry.pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=10)

        self.send_button = tk.Button(
            self.message_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

    def send_message(self):
        message = self.message_entry.get("1.0", tk.END).strip()
        if message and self.current_chat_user_id:
            self.app_logic.send_message_via_socket(
                self.current_chat_user_id, message)
            self.message_entry.delete("1.0", tk.END)
            self.display_message("You", message, "self")

    def display_message(self, sender, message, origin):
        self.chat_text.tag_config(
            "self", foreground="blue", font=("Verdana", 10))
        self.chat_text.tag_config(
            "other", foreground="green", font=("Verdana", 10))

        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.insert(tk.END, f"{sender}: {message}\n", (origin,))
        self.chat_text.config(state=tk.DISABLED)

    def load_chat(self, id, name):
        self.current_chat_user_id = id
        self.current_chat_user_name = name

        sym_key = self.app_logic.getOrExchangeSymKeysEndToEnd(
            self.current_chat_user_id)

        print(sym_key)
        if not sym_key:
            messagebox.showwarning(
                "Warning", "The other user must be connected to innitiate an end to end chat")
            return None
        # Update focused chat on the server
        self.app_logic.update_focused_chat(self.current_chat_user_id)

        # exchange private key if it has not been done

        # print("END EXCHANGE: ", sym_key)
        # Update the UI to reflect the selected chat
        self.chat_label.config(
            text=f"Hi {self.app_logic.username}! Chatting with {name}")

        # Clear the chat window
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.delete("1.0", tk.END)

        # Fetch and display the conversation

        conversation = self.app_logic.get_conversation(
            self.current_chat_user_id)
        for message_data in conversation:
            origin_user_id = message_data["origin_user_id"]

            decrypted_message = self.app_logic.encryption.decrypt_body(
                message_data["message"], "sym", "json", self.app_logic.encryption.asymmetric_decrypt(self.app_logic.json_keys.search_entry(str(self.current_chat_user_id))))

            if str(origin_user_id) == str(
                    self.app_logic.user_id):
                sender_name = "You"
                origin = "self"
            else:
                sender_name = name
                origin = "other"

            self.display_message(sender_name, decrypted_message, origin)

        # Disable the chat window for new messages
        self.chat_text.config(state=tk.DISABLED)

# display para salir de la sesión
    def log_out(self, session_check=False):
        self.display_loading()
        log_out_thread = threading.Thread(
            target=self._log_out_thread)
        log_out_thread.start()

    def _log_out_thread(self):
        self.app_logic.logout()
        self.display_login()

    def login(self):
        print("LOGGING IN...")
        username = self.username_val.get()
        password = self.password_val.get()
        login_thread = threading.Thread(
            target=self._login_thread, args=(username, password))
        login_thread.start()
        self.display_loading()

    def _login_thread(self, username, password):
        result = self.app_logic.login(username, password)
        # print(result["message"])

        # After the login logic completes, update the UI in the main thread
        if result["status"]:
            self.display_chat()
        else:
            self.root.after(1, lambda: messagebox.showerror(
                "Error", result["message"]))
            self.display_login()

    def register(self):
        print("Registering...")
        username = self.username_val.get()
        password = self.password_val.get()
        repeat_password = self.repeat_password_val.get()
        self.display_loading()
        register_thread = threading.Thread(
            target=self._register_thread, args=(username, password, repeat_password))
        register_thread.start()

    def _register_thread(self, username, password, repeat_password):
        result = self.app_logic.register(
            username, password, repeat_password)
        if result["status"]:
            self.display_login()
            messagebox.showinfo("Success", result["message"])

        else:
            self.display_register()
            messagebox.showerror("Error", result["message"])


if __name__ == "__main__":
    root = tk.Tk()
    app = UI(root)

    root.mainloop()
