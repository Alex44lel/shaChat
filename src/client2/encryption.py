# Importa las funciones para menejar cifrado asimétrico con RSA y el esquema de relleno (padding), que es necesario para el cifrado RSA.
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Importa funciones de serialización, que se usan para exportar e importar claves
from cryptography.hazmat.primitives import serialization
# Algoritmo para cifrar mensajes y verificar su autenticidad.
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import base64
import json
import os
# Para manejar los colores de la terminal
import colorama
from termcolor import colored

# Para manejar horas en los mensajes de registro
from datetime import datetime

# Inicializamos el uso de los colores ANSI en la terminal
colorama.init()

# Definimos la función encryption, donde el constructor recibe: owner que es UNAUTHENTICATED USER por defecto y las rutas de las claves.


class Encryption:
    def __init__(self, owner="UNAUTHENTICATED USER", private_key_path="private_asym_pre.pem", public_key_path="public_asym_pre.pem"):
        # RSA keys
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.owner = owner

        # Genera las claves asimetricas
        self.generate_asym_keys()
        self._load_public_key_ac_from_cert_path("../ac1/ac1cert.pem")

    def _load_public_key_ac_from_cert_path(self, path):
        with open(path, "rb") as cert_file:
            cert_data = cert_file.read()

        cert_obj = x509.load_pem_x509_certificate(cert_data)

        self.public_key_object_ac1 = cert_obj.public_key()

    # Método para cargar mensajes, se le atribuyen ciertas características

    def log_message(self, state=None, action_type=None, key_length=None, algorithm=None, message=None, level="INFO"):

        # Así será printeado el owner
        owner_text = colored(f"[{self.owner}]", "magenta", attrs=["bold"])

        # Diccionario con los diferentes niveles de mensajes y como serán printeados en la terminal
        level_colors = {
            "INFO": colored(level, "blue", attrs=["bold"]),
            "WARNING": colored(level, "yellow", attrs=["bold"]),
            "ERROR": colored(level, "red", attrs=["bold"])
        }

        # Selecciona el color correspondiente para el nivel actual de log.
        # Si el nivel especificado no está en el diccionario, por defecto el nivel se mostrará en blanco.
        level_text = level_colors.get(level, colored(level, "white"))

        timestamp = colored(f"{datetime.now()}", "green")
        # Combina el timestamp, el nombre del propietario y el nivel del mensaje.
        # Este mensaje se utilizará como parte del mensaje completo que se imprimirá en la consola.
        base_message = f"{timestamp} {owner_text} {level_text}"

        # Si el estado es "Starting" printeamos de esta forma
        if state == "Starting":
            state_text = colored(state, "cyan", attrs=[
                "bold"])
            full_message = (
                f"{base_message}: {state_text} {action_type} of {message} "
                f"using {algorithm} with key length {key_length} bits"
            )

        # Si el estado es "End" printeamos de esta forma
        elif state == "End":
            state_text = colored(state, "green", attrs=["bold"])
            full_message = (
                f"{base_message}: {state_text} of {action_type} with result: {message} "
                f"using {algorithm} with key length {key_length} bits"
            )

        # Si el estado es otro printamos así
        elif state == "other":
            action_type = colored(action_type, "yellow", attrs=["bold"])
            full_message = (
                f"{base_message}: {action_type} {message} "
            )

        print(full_message)

    # Método privado para generar las claves asimétricas
    def generate_asym_keys(self, password=False):
        if not password:
            self.private_key_path = "private_asym_pre.pem"
            self.public_key_path = "public_asym_pre.pem"
        # Verifica que existen los archivos de clave pública y clave privada en el sistema
        if os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path):
            # carga la clave privada desde el archivo en el caso que exista y genera su clave pública correspondiente
            print("AQUI2")
            print(self.private_key_path)
            print(self.public_key_path)
            self.private_key = self.load_private_key(password)
            self.public_key = self.private_key.public_key()

        # Si no existen las claves se generan
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            # Crea la clave pública correspondiente a la clave privada correspondiente
            self.public_key = self.private_key.public_key()
            # para guardar las claves en archivos
            self.save_keys_asym(password)
            self.log_message("other", f"Asym Key generation", None,
                             None, f"using RSA, result: {self.public_key} of lenght 2048")

    # Método para guardar las claves asimétricas
    def save_keys_asym(self, password=None):
        # abre (o crea si no existe) el archivo donde se guardará la clave privada en modo escritura binaria.
        with open(self.private_key_path, 'wb') as private_file:

            encryption = (
                serialization.BestAvailableEncryption(password.encode()) if password
                else serialization.NoEncryption()
            )
            # Convierte la clave privada en una secuencia de bytes que puede ser escrita en el archivo
            private_file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=encryption
                )
            )

        # Guardamos la clave pública
        with open(self.public_key_path, 'wb') as public_file:
            public_file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        self.log_message("other", f"Asym keys saved", None,
                         None, "")

    # Método que se encarga de eliminar y regenerar las claves asimétricas.
    def generate_logged_asymetric(self, password=None, user_id=False):
        if os.path.exists(self.private_key_path):
            os.remove(self.private_key_path)
        if os.path.exists(self.public_key_path):
            os.remove(self.public_key_path)

        self.log_message("other", f"Regenerate asym keys", None,
                         None, "")

        self.private_key_path = f"private_asym_{user_id}.pem"
        self.public_key_path = f"public_asym_{user_id}.pem"

        print("AQUI")
        self.generate_asym_keys(password)

    # Este método tiene como objetivo cargar una clave privada asimétrica desde un archivo.
    def load_private_key(self, password=None):
        # Abre el archivo en lectura binaria(rb).
        with open(self.private_key_path, 'rb') as file:
            private_asym_key = serialization.load_pem_private_key(
                file.read(),
                password=password.encode() if password else None
            )

        return private_asym_key

    # Método que genera la clave simetrica
    def generate_symetric_key(self):
        # Genera la clave simetrica con el algoritmo ChaCha20Poly1305
        key = ChaCha20Poly1305.generate_key()
        # Convierte la clave generada (es binaria) a formato Base64 y la pasa a texto gracias al decode utf-8
        # (Esto se hace para que sea almacenada o transmitida por texto)
        key = base64.b64encode(key).decode('utf-8')
        self.log_message("other", f"Symetric Key generation", None,
                         None, f"using ChaCha20Poly1305, result: {key} of lenght {len(key)*8}")
        return key

    # Método que realiza un cifrado simetrico autenticado, text es el mensaje a cifrar, key es la clave que usará para el cifrado y
    # add son datos adicionales que se incluyen en el proceso de autentificación pero no se cifran
    def symmetric_encrypt_authenticated(self, text, key, aad):

        # ADD LOG:
        self.log_message("Starting", "Encryption", len(
            key)*8, "ChaCha20Poly1305", text)

        # pasamos la cadena de texto a binario para volverlo a pasar a texto para un correcto cifrado posterior
        key = base64.b64decode(key.encode("utf-8"))
        # Algoritmo ChaCha
        chacha = ChaCha20Poly1305(key)
        # Genera un número arbitrario que solo se usa una vez, esto gRntiza que el mismo mensaje difrado con la misma
        # clave de un resultado diferente
        nonce = os.urandom(12)
        encoded_nonce = base64.b64encode(nonce).decode(
            "utf-8")

        # Additional data
        aad = aad.encode("utf-8")
        encoded_aad = base64.b64encode(aad).decode(
            "utf-8")
        text = text.encode("utf-8")
        # Se realiza el cifrado del texto con ChaCha junto nonce y add.
        cypher_text = chacha.encrypt(nonce, text, aad)
        cypher_text_encoded = base64.b64encode(cypher_text).decode("utf-8")

        # ADD LOG:
        self.log_message("End", "Encryption", len(key)*8,
                         "ChaCha20Poly1305", cypher_text_encoded)

        return [cypher_text_encoded, encoded_nonce, encoded_aad]

    # Método de desencriptado simetrico
    def symmetric_decrypt(self, cypher_text_encoded, key, encoded_nonce, encoded_aad):
        # ADD LOG:
        self.log_message("Starting", "Decryption", len(
            key)*8, "ChaCha20Poly1305", cypher_text_encoded)

        # Hacemos el chacha de la key
        key = base64.b64decode(key.encode("utf-8"))
        chacha = ChaCha20Poly1305(key)
        # Desciframos el nonce y el add
        nonce = base64.b64decode(encoded_nonce.encode("utf-8"))
        aad = base64.b64decode(encoded_aad.encode("utf-8"))
        # Pasamos el texto cifrado al texto original
        cypher_text = base64.b64decode(cypher_text_encoded.encode("utf-8"))
        original_text = chacha.decrypt(nonce, cypher_text, aad)
        original_text = original_text.decode("utf-8")
        # ADD LOG:
        self.log_message("End", "Decryption", len(key)*8,
                         "ChaCha20Poly1305", original_text)

        return original_text

    # Método de encriptación con clave pública
    def asymmetric_encrypt_with_external_public_key(self, public_key, text):
        # ADD LOG:
        self.log_message("Starting", "Asymmetric Encryption",
                         2048, "RSA", text)

        # Carga la clave pública desde la cadena en formato PEM
        if isinstance(public_key, str):
            public_key = serialization.load_pem_public_key(
                public_key.encode('utf-8')
            )

        # Usa la clave pública para cifrar el texto, siendo PKCS1v15 el esquema de relleno para el cifrado, haciendo el proceso más seguro
        cipher_text = public_key.encrypt(
            text.encode(),
            padding.PKCS1v15()
        )
        result = base64.b64encode(cipher_text).decode('utf-8')

        # ADD LOG:

        self.log_message("End", "Asymmetric Encryption", 2048,
                         "RSA", result)

        return result

    # Método de descifrado asimétrico
    def asymmetric_decrypt(self, cipher_text):
        # ADD LOG:
        self.log_message("Starting", "Asymmetric Decryption",
                         2048, "RSA", cipher_text)

        cipher_text = base64.b64decode(cipher_text)
        # Desencriptamos usando la clave privada
        original_text = self.private_key.decrypt(
            cipher_text,
            padding.PKCS1v15()
        )
        print(original_text)
        result = original_text.decode('utf-8')
        # ADD LOG:
        self.log_message("End", "Asymmetric Decryption", 2048,
                         "RSA", result)

        return result

    def encrypt_for_json_keys(self, sym_key):

        self.log_message("Starting", "Asymmetric Encryption",
                         2048, "RSA", sym_key)

        cipher_text = self.public_key.encrypt(
            sym_key.encode("utf-8"),
            padding.PKCS1v15()
        )
        result = base64.b64encode(cipher_text).decode('utf-8')

        # ADD LOG:
        self.log_message("End", "Asymmetric Encryption", 2048,
                         "RSA", result)

        return result
    # Método que tiene como objetivo exportar la clave pública para que sea transmitida o almacenada.

    def export_public_key(self):
        # Export in PEM format
        public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.log_message("other", f"Exporting public key", None,
                         None, f"result: {public_key} of lenght {len(public_key)*8}")
        return public_key

    # Método que cifra el cuerpo de datos
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
        else:
            return payload.json()

    # Método para descifrar el cuerpo
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

    # ---------------SIGNING AND VERIFICATION----------------
    # Metodo que firma
    def sign(self, message):
        self.log_message("Starting", f"Signing_message", 2048,
                         "RSA", f"Message: {message}")
        # Método que se encarga de hashear una contraseña junto a un salt

        message_bytes = message.encode("utf-8")
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        self.log_message("End", f"Signing_message", 2048,
                         "RSA", f"Signature: {message}")

        return signature

    def verify(self, message, signature, public_key=None):
        self.log_message("Starting", f"Verifying_signature of a message", 2048,
                         "RSA", f"Message: {message}")

        if not public_key:
            public_key = self.public_key

        message_bytes = message.encode("utf-8")

        try:
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

        except Exception as e:
            print("Signature is not valid: ", e)
            self.log_message("End", f"Verifying_signature of a message", 2048,
                             "RSA", f"State: False")
            return False

        self.log_message("End", f"Verifying_signature", 2048,
                         "RSA", f"State: True")
        return True

    # ------------------CERTIFICATE-------------------------
    def generate_certificate_request(self, user_id):
        # Generate a CSR
        self.log_message("other", f"Generating certificate request", None,
                         None, f"")
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.GIVEN_NAME, str(user_id)),
        ])).sign(self.private_key, hashes.SHA256())
        # Write our CSR out to disk.
        with open(f"../ac1/solicitudes/csr_{user_id}.pem", "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

    def verify_certificate_and_get_public_key(self, certificate):
        # el certificado viene en un string base 64
        cert_obj = x509.load_pem_x509_certificate(
            base64.b64decode(certificate.encode("utf-8")))

        # verification....
        self.log_message("Starting", f"Verifying_signature of client certificate", 2048,
                         "RSA", f"Message:")

        try:
            self.public_key_object_ac1.verify(
                cert_obj.signature,
                cert_obj.tbs_certificate_bytes,
                cert_obj.signature_algorithm_parameters,
                cert_obj.signature_hash_algorithm
            )
            public_key = cert_obj.public_key()
            # public key object
            self.log_message("End", f"Verifying_signature of client certificate", 2048,
                             "RSA", f"State: True")
            return public_key

        except Exception as e:
            print("Signature is not valid: ", e)
            self.log_message("End", f"Verifying_signature", 2048,
                             "RSA", f"State: False")
            return False

    def hash_salt(self, password, salt):
        if salt is None:
            salt = os.urandom(32)
        else:
            salt = base64.b64decode(salt)
        salt_base64 = base64.b64encode(salt).decode('utf-8')
        # Crea un nuevo objeto de hash utilizando el algoritmo SHA-256 y le añade la contraseña y el salt
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode('utf-8'))
        digest.update(salt)
        # Finaliza el proceso de hash y genera el hash resultante
        password_hashed = digest.finalize()
        password_hashed_base64 = base64.b64encode(
            password_hashed).decode('utf-8')

        self.log_message("other", f"Password hashed", None,
                         None, f"result: {password_hashed_base64}")
        return password_hashed_base64, salt_base64
