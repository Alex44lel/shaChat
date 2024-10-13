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


SERVER = "http://localhost:5000"


class ChatLogic:
    def __init__(self):
        self.session_token = None
        self.username = None
        self.user_id = None
        self.json_keys = None
        self.encryption = Encryption()
        self.server_public_key = None
        self._getServerPublicKey()

    def _getServerPublicKey(self):
        response = requests.get(
            f"{SERVER}/get-public-key")

        if response.status_code == 200:
            self.server_public_key = response.json().get("public-key")
            print("SERVER PUBLIC KEY:", self.server_public_key)

        else:
            print("unable to get public key")

    def getAllUsers(self):
        response = requests.get(
            f"{SERVER}/get-all-users-names/{self.user_id}")

        if response.status_code == 200:
            response_body = self.encryption.decrypt_body(
                response, "sym", "response", self.json_keys.search_entry("server"))
            return response_body.get("all_users")
        else:
            print("unable to get all users")

    def checkSessionToken(self, display_login, display_chat, log_out):
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

            print(response_body.get('message'))
            self.username = response_body.get("username")
            self.user_id = response_body.get("user_id")
            if response.status_code == 200:
                self.session_token = session_token
                print("session is valid")
                self.json_keys = JsonManager(f"json_keys_{self.user_id}.json")
                display_chat()

            else:
                print("session token has expired")
                log_out(True)
                return

        except FileNotFoundError:
            print("no session token file")
            display_login()
            return

    def sendSymmetricKeyToServer(self):
        # TODO: ENCRYPT USING ASSYMETRIC
        key = self.encryption.generate_symetric_key()
        print("THIS IS THE KEY IN THE CLIENT:", key)
        body = {"username": self.username,
                "sym_key": key, "user_id": self.user_id}
        response = requests.post(
            f"{SERVER}/receive-symmetric-key-from-client", json=self.encryption.get_encrypted_body(body, "asym", self.server_public_key))

        if response.status_code == 200:
            self.json_keys.add_entry("server", key)

        return [response.status_code, response.json().get('message')]

    def logout(self):
        body = {"session_token": self.session_token, "user_id": self.user_id}
        body_encrypted = self.encryption.get_encrypted_body(
            body, "asym", self.server_public_key)
        body_encrypted["user_public_key"] = self.encryption.export_public_key(
        )
        # TODO: ENCRYPT USING ASSYMETRIC
        response = requests.post(
            f"{SERVER}/logout", json=body_encrypted)
        response_body = self.encryption.decrypt_body(
            response, "asym", "response")

        # delete server sym
        if self.json_keys != None:
            self.json_keys.delete_entry("server")
        # delete own asym keys
        self.encryption.regenerate_keys_asym()
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
            with open("session_token.json", "w") as session_token_file:
                json.dump({"session_token": self.session_token},
                          session_token_file)
            self.json_keys = JsonManager(f"json_keys_{self.user_id}.json")
            result = self.sendSymmetricKeyToServer()
            print("PARA RETORNAR")
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
        self.logic = ChatLogic()
        self.root.title("SHAchat, secure chatting for free")
        self.root.geometry("1200x600")

        self.logic.checkSessionToken(
            self.display_login, self.display_chat, self.log_out)

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def display_loading(self):
        self.clear_screen()

        # Create a frame for the loading screen
        loading_frame = tk.Frame(self.root, bg="white")
        loading_frame.pack(fill=tk.BOTH, expand=True)

        # Add a label to show the loading message
        loading_label = tk.Label(
            loading_frame, text="Loading, please wait...", font=("Verdana", 16), bg="white")
        loading_label.pack(pady=20)

        # Optionally, you can add an animated progress bar or a spinning text effect
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
        self.users = self.logic.getAllUsers()
        # ["Alice", "Bob", "Charlie charlie charlie", "Dave"]

        self.user_buttons = []

        tk.Label(self.user_list_frame, text="Available users",
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

        # Use pack with side=tk.LEFT to place them next to each other
        self.chat_label = tk.Label(
            self.header_frame, text="Select a user to start chatting", bg="white", font=("Vedana", 14, "bold"))
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

        self.current_user = None

    def send_message(self):
        pass

    def load_chat(self):
        pass

    def log_out(self, session_check=False):
        self.display_loading()
        log_out_thread = threading.Thread(
            target=self._log_out_thread)
        log_out_thread.start()

    def _log_out_thread(self):
        self.logic.logout()
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
        result = self.logic.login(username, password)
        print(result["message"])

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
        result = self.logic.register(
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
