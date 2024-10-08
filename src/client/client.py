import tkinter as tk
from tkinter import messagebox
from jsonManager import JsonManager
import requests
from encryption import Encryption
import json


SERVER = "http://localhost:5000"


class ChatLogic:
    def __init__(self):
        self.session = None
        self.username = None
        self.json_keys = JsonManager("json_keys.json")
        self.encryption = Encryption()
        self.server_public_key = None
        self._getServerPublicKey()

    def _getServerPublicKey(self):
        response = requests.get(
            f"{SERVER}/get-public-key")

        if response.status_code == 200:
            self.server_public_key = response.json().get("public-key")
            print(self.server_public_key)

        else:
            print("unable to get public key")

    def sendSymmetricKeyToServer(self, username):
        key = self.encryption.generate_symetric_key()
        self.json_keys.add_entry("server", key)

        body = {"username": username, "sym_key": key}
        response = requests.post(
            f"{SERVER}/receive-symmetric-key-from-client", json=self.encryption.get_encrypted_body(body, "asym", self.server_public_key))

        if response.status_code == 200:
            self.json_keys.add_entry("server", key)

        return [response.status_code, response.json().get('message')]

    def login(self, username, password):
        if not username or not password:
            return {"status": 0, "message": "you must cover all the inputs"}

        body = {"username": username, "password": password}
        response = requests.post(
            f"{SERVER}/login", json=self.encryption.get_encrypted_body(body, "asym", self.server_public_key))

        if response.status_code == 200:
            self.username = username
            self.session_token = response.json().get('session_token')
            result = self.sendSymmetricKeyToServer(username)
            if result[0] != 200:
                return {"status": 0, "message": result[1]}
            return {"status": 1, "message": response.json().get('message')}
        else:
            return {"status": 0, "message": response.json().get('message')}

    def register(self, username, password, repeat_password):
        if not username or not password or not repeat_password:
            return {"status": 0, "message": "you must cover all the inputs"}

        if password != repeat_password:
            return {"status": 0, "message": "passwords do not match"}

        body = {"username": username, "password": password}
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

        self.display_login()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

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

        self.users = ["Alice", "Bob", "Charlie charlie charlie", "Dave"]
        self.user_buttons = []

        tk.Label(self.user_list_frame, text="Available users",
                 bg="lightgray", font=("Vedana", 11, "bold")).pack(pady=10)
        for user in self.users:
            button = tk.Button(self.user_list_frame, text=user,
                               command=lambda u=user: self.load_chat(u))
            button.pack(fill=tk.X, pady=0, padx=20)
            self.user_buttons.append(button)

        # Chat display frame
        self.chat_display_frame = tk.Frame(self.root, bg="white")
        self.chat_display_frame.pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.chat_label = tk.Label(
            self.chat_display_frame, text="Select a user to start chatting", bg="white", font=("Vedana", 14, "bold"))
        self.chat_label.pack(pady=10)

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

    def login(self):
        print("LOGGING IN...")
        result = self.logic.login(
            self.username_val.get(), self.password_val.get())

        if result["status"]:
            messagebox.showinfo("Success", result["message"])
            self.display_chat()
        else:
            messagebox.showerror("Error", result["message"])

    def register(self):
        print("Registering...")
        result = self.logic.register(
            self.username_val.get(), self.password_val.get(), self.repeat_password_val.get())
        if result["status"]:
            messagebox.showinfo("Success", result["message"])
        else:
            messagebox.showerror("Error", result["message"])


if __name__ == "__main__":
    root = tk.Tk()
    app = UI(root)
    root.mainloop()
