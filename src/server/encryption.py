
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes

import base64
import json
import os
import colorama
from termcolor import colored
from datetime import datetime

colorama.init()


class Encryption:
    def __init__(self, private_key_path="private_asym.pem", public_key_path="public_asym.pem"):
        # RSA keys
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.owner = "SERVER"

        self._generate_asym_keys()

    from termcolor import colored

    def log_message(self, state, action_type, key_length, algorithm, message, destination, level="INFO"):
        owner_text = colored(f"[{self.owner}", "magenta", attrs=["bold"])
        destination_text = colored(f"{destination}]", "orange", attrs=["bold"])

        level_colors = {
            "INFO": colored(level, "blue", attrs=["bold"]),
            "WARNING": colored(level, "yellow", attrs=["bold"]),
            "ERROR": colored(level, "red", attrs=["bold"])
        }
        level_text = level_colors.get(level, colored(level, "white"))

        timestamp = colored(f"{datetime.now()}", "green")
        base_message = f"{timestamp} {owner_text} to {destination_text} {level_text}"

        if state == "Starting":
            state_text = colored(state, "cyan", attrs=[
                "bold"])
            full_message = (
                f"{base_message}: {state_text} {action_type} of {message} "
                f"using {algorithm} with key length {key_length} bits"
            )
        elif state == "End":
            state_text = colored(state, "green", attrs=["bold"])
            full_message = (
                f"{base_message}: {state_text} of {action_type} with result: {message} "
                f"using {algorithm} with key length {key_length} bits"
            )

    # Print the formatted log message
    print(full_message)

    # Print the styled log message
    # print(f"{datetime.now()} {title_text} {level_text}: {message_text}")

    def _generate_asym_keys(self):
        if os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path):
            self.private_key = self.load_private_key()
            self.public_key = self.private_key.public_key()

        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()
            self.save_keys_asym()

    def save_keys_asym(self):
        # saving private key
        with open(self.private_key_path, 'wb') as private_file:
            private_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # saving public key
        with open(self.public_key_path, 'wb') as public_file:
            public_file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    def regenerate_keys_asym(self):
        if os.path.exists(self.private_key_path):
            os.remove(self.private_key_path)
        if os.path.exists(self.public_key_path):
            os.remove(self.public_key_path)

        self._generate_asym_keys()

    def load_private_key(self):
        with open(self.private_key_path, 'rb') as file:
            private_asym_key = serialization.load_pem_private_key(
                file.read(),
                password=None
            )
        return private_asym_key

    def generate_symetric_key(self):
        # symmetric key in base64 bytes
        key = ChaCha20Poly1305.generate_key()
        key = base64.b64encode(key).decode('utf-8')
        return key

    # fernet already returns things in base64

    def symmetric_encrypt_authenticated(self, text, key, aad):
        # we might need to convert the key back to bytes
        key = base64.b64decode(key.encode("utf-8"))
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        encoded_nonce = base64.b64encode(nonce).decode(
            "utf-8")  # this is send in the request
        aad = aad.encode("utf-8")
        encoded_aad = base64.b64encode(aad).decode(
            "utf-8")
        text = text.encode("utf-8")
        cypher_text = chacha.encrypt(nonce, text, aad)
        cypher_text_encoded = base64.b64encode(cypher_text).decode("utf-8")

        return [cypher_text_encoded, encoded_nonce, encoded_aad]
        # cipher_text = Fernet(key).encrypt(text.encode("utf-8"))
        # return cipher_text.decode("utf-8")

    def symmetric_decrypt(self, cypher_text_encoded, key, encoded_nonce, encoded_aad):
        # Decrypting using Fernet
        key = base64.b64decode(key.encode("utf-8"))
        chacha = ChaCha20Poly1305(key)
        nonce = base64.b64decode(encoded_nonce.encode("utf-8"))
        aad = base64.b64decode(encoded_aad.encode("utf-8"))
        cypher_text = base64.b64decode(cypher_text_encoded.encode("utf-8"))
        original_text = chacha.decrypt(nonce, cypher_text, aad)
        return original_text.decode('utf-8')

    def asymmetric_encrypt_with_external_public_key(self, key_pem, text):
        # Encrypting using the public key with (PKCS1v15 padding)

        public_key = serialization.load_pem_public_key(
            key_pem.encode('utf-8')
        )
        cipher_text = public_key.encrypt(
            text.encode(),
            padding.PKCS1v15()
        )
        return base64.b64encode(cipher_text).decode('utf-8')

    def asymmetric_decrypt(self, cipher_text):
        # Decrypting using the private key (PKCS1v15 padding)
        cipher_text = base64.b64decode(cipher_text)
        original_text = self.private_key.decrypt(
            cipher_text,
            padding.PKCS1v15()
        )
        return original_text.decode('utf-8')

    def export_public_key(self):
        # Export in PEM format
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        return public_key_bytes

    def get_encrypted_body(self, body, method, key, aad=None):
        if method == "asym":
            message_encrypted = self.asymmetric_encrypt_with_external_public_key(
                key, json.dumps(body))
            return {"cypher_message": message_encrypted}
        else:
            print(key)
            message_encrypted, encoded_nonce, encoded_aad = self.symmetric_encrypt_authenticated(
                json.dumps(body), key, aad)

            return {"cypher_message": message_encrypted, "encoded_nonce": encoded_nonce, "encoded_aad": encoded_aad}

    def json_tranformer(self, payload, payload_type):
        if payload_type == "request":
            return payload.get_json()
        else:  # payload_type is response
            return payload.json()

    def decrypt_body(self, payload, method, payload_type, key=None):
        if payload_type != "json":
            payload = self.json_tranformer(
                payload, payload_type)

        if method == "asym":
            cypher_message = payload.get("cypher_message")
            message_decrypted = json.loads(
                self.asymmetric_decrypt(cypher_message))
        else:

            cypher_message = payload.get("cypher_message")
            encoded_nonce = payload.get("encoded_nonce")
            encoded_aad = payload.get("encoded_aad")

            message_decrypted = json.loads(
                self.symmetric_decrypt(
                    cypher_message, key, encoded_nonce, encoded_aad)
            )

        return message_decrypted

    def hash_salt(self, password, salt):
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
