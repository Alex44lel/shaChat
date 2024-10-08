
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import base64
import json


class Encryption:
    def __init__(self):
        # RSA keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def generate_symetric_key(self):
        # symmetric key in base64 bytes
        return Fernet.generate_key().decode('utf-8')

    # fernet already returns things in base64
    def symmetric_encrypt(self, text, key):
        cipher_text = Fernet(key).encrypt(text.encode("utf-8"))
        return cipher_text.decode("utf-8")

    def symmetric_decrypt(self, cipher_text):
        # Decrypting using Fernet
        original_text = self.fernet.decrypt(cipher_text.encode("utf-8"))
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

    def get_encrypted_body(self, body, method, key=None):
        if method == "asym":
            body_encrypted = self.asymmetric_encrypt_with_external_public_key(
                key, json.dumps(body))

        else:
            pass

        return {"cypher_body": body_encrypted}

    def decrypt_body(self, cypher_body, method, key=None):
        if method == "asym":
            body_decrypted = json.loads(self.asymmetric_decrypt(cypher_body))
        else:
            pass

        return body_decrypted
