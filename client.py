import tkinter as tk
from tkinter import messagebox
import requests

SERVER = "http://localhost:5000"


class ChatLogic:
    def __init__(self):
        self.session = None
        self.username = None
        pass

    def login(self, username, password):

        if not username or not password:
            return {"status": 0, "message": "you must cover all the inputs"}

        response = requests.post(
            f"{SERVER}/login", json={"username": username, "password": password})

        if response.status_code == 200:
            self.username = username
            self.session_token = response.json().get('session_token')
            return {"status": 1, "message": response.json().get('message')}
        else:
            return {"status": 0, "message": response.json().get('message')}

    def register(self, username, password, repeat_password):
        if not username or not password or not repeat_password:
            return {"status": 0, "message": "you must cover all the inputs"}

        if password != repeat_password:
            return {"status": 0, "message": "passwords do not match"}

        response = requests.post(
            f"{SERVER}/register", json={"username": username, "password": password})

        if response.status_code == 201:
            return {"status": 1, "message": response.json().get('message')}
        else:
            return {"status": 0, "message": response.json().get('message')}


class UI:
    def __init__(self, root):
        self.root = root
        self.logic = ChatLogic()
        self.root.title("SHAchat, secure chatting for free")
        self.root.geometry("600x450")

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

    def login(self):
        print("LOGGING IN...")
        result = self.logic.login(
            self.username_val.get(), self.password_val.get())
        if result["status"]:
            messagebox.showinfo("Success", result["message"])
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
