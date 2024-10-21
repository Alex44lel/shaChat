#Importa las funciones para menejar cifrado asimétrico con RSA y el esquema de relleno (padding), que es necesario para el cifrado RSA.
from cryptography.hazmat.primitives.asymmetric import rsa, padding
#Importa funciones de serialización, que se usan para exportar e importar claves
from cryptography.hazmat.primitives import serialization
#Algoritmo para cifrar mensajes y verificar su autenticidad.
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes

import base64
import json
import os
#Para manejar los colores de la terminal
import colorama
from termcolor import colored

#Para manejar horas en los mensajes de registro
from datetime import datetime

#Inicializamos el uso de los colores ANSI en la terminal
colorama.init()

#Definimos la función encryption, donde el constructor recibe: owner que es UNAUTHENTICATED USER por defecto y las rutas de las claves.
class Encryption:
    def __init__(self, owner="UNAUTHENTICATED USER", private_key_path="private_asym.pem", public_key_path="public_asym.pem"):
        # RSA keys
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.owner = owner

        #Genera las claves asimetricas
        self._generate_asym_keys()

    from termcolor import colored

    #Método para cargar mensajes, se le atribuyen ciertas características
    def log_message(self, state=None, action_type=None, key_length=None, algorithm=None, message=None, level="INFO"):

        #Así será printeado el owner
        owner_text = colored(f"[{self.owner}]", "magenta", attrs=["bold"])

        #Diccionario con los diferentes niveles de mensajes y como serán printeados en la terminal
        level_colors = {
            "INFO": colored(level, "blue", attrs=["bold"]),
            "WARNING": colored(level, "yellow", attrs=["bold"]),
            "ERROR": colored(level, "red", attrs=["bold"])
        }

        #Selecciona el color correspondiente para el nivel actual de log.
        #Si el nivel especificado no está en el diccionario, por defecto el nivel se mostrará en blanco.
        level_text = level_colors.get(level, colored(level, "white"))

        timestamp = colored(f"{datetime.now()}", "green")
        #Combina el timestamp, el nombre del propietario y el nivel del mensaje. 
        #Este mensaje se utilizará como parte del mensaje completo que se imprimirá en la consola.
        base_message = f"{timestamp} {owner_text} {level_text}"

        #Si el estado es "Starting" printeamos de esta forma
        if state == "Starting":
            state_text = colored(state, "cyan", attrs=[
                "bold"])
            full_message = (
                f"{base_message}: {state_text} {action_type} of {message} "
                f"using {algorithm} with key length {key_length} bits"
            )
        
        #Si el estado es "End" printeamos de esta forma
        elif state == "End":
            state_text = colored(state, "green", attrs=["bold"])
            full_message = (
                f"{base_message}: {state_text} of {action_type} with result: {message} "
                f"using {algorithm} with key length {key_length} bits"
            )

        #Si el estado es otro printamos así
        elif state == "other":
            action_type = colored(action_type, "yellow", attrs=["bold"])
            full_message = (
                f"{base_message}: {action_type} {message} "
            )

        print(full_message)

    #Método privado para generar las claves asimétricas
    def _generate_asym_keys(self):
        #Verifica que existen los archivos de clave pública y clave privada en el sistema
        if os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path):
            #carga la clave privada desde el archivo en el caso que exista y genera su clave pública correspondiente
            self.private_key = self.load_private_key()
            self.public_key = self.private_key.public_key()

        #Si no existen las claves se generan
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            #Crea la clave pública correspondiente a la clave privada correspondiente
            self.public_key = self.private_key.public_key()
            #para guardar las claves en archivos
            self.save_keys_asym()
            self.log_message("other", f"Asym Key generation", None,
                             None, f"using RSA, result: {self.public_key} of lenght 2048")

    def save_keys_asym(self):
        # saving private key
        #abre (o crea si no existe) el archivo donde se guardará la clave privada en modo escritura binaria. 
        with open(self.private_key_path, 'wb') as private_file:
            private_file.write(
                #convierte la clave privada en una secuencia de bytes que puede ser escrita en el archivo
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
        self.log_message("other", f"Asym keys saved", None,
                         None, "")

    #Método que se encarga de eliminar y regenerar las claves asimétricas.
    def regenerate_keys_asym(self):
        if os.path.exists(self.private_key_path):
            os.remove(self.private_key_path)
        if os.path.exists(self.public_key_path):
            os.remove(self.public_key_path)

        self.log_message("other", f"Regenerate asym keys", None,
                         None, "")

        self._generate_asym_keys()

    #Este método tiene como objetivo cargar una clave privada asimétrica desde un archivo.
    def load_private_key(self):
        #Abre el archivo en lectura binaria(rb).
        with open(self.private_key_path, 'rb') as file:
            private_asym_key = serialization.load_pem_private_key(
                file.read(),
                password=None
            )

        return private_asym_key

    #Método que genera la clave simetrica
    def generate_symetric_key(self):
        # symmetric key in base64 bytes

        #Genera la clave simetrica con el algoritmo ChaCha20Poly1305
        key = ChaCha20Poly1305.generate_key()
        #Convierte la clave generada (es binaria) a formato Base64 y la pasa a texto gracias al decode utf-8
        #(Esto se hace para que sea almacenada o transmitida por texto)
        key = base64.b64encode(key).decode('utf-8')
        self.log_message("other", f"Symetric Key generation", None,
                         None, f"using ChaCha20Poly1305, result: {key} of lenght {len(key)*8}")
        return key

    # fernet already returns things in base64

    #Método que realiza un cifrado simetrico autenticado, text es el mensaje a cifrar, key es la clave que usará para el cifrado y
    #add son datos adicionales que se incluyen en el proceso de autentificación pero no se cifran
    def symmetric_encrypt_authenticated(self, text, key, aad):

        # ADD LOG:
        self.log_message("Starting", "Encryption", len(
            key)*8, "ChaCha20Poly1305", text)

        # pasamos la cadena de texto a binario para volverlo a pasar a texto para un correcto cifrado posterior
        key = base64.b64decode(key.encode("utf-8"))
        #Algoritmo ChaCha
        chacha = ChaCha20Poly1305(key)
        #Genera un número arbitrario que solo se usa una vez, esto gRntiza que el mismo mensaje difrado con la misma
        #clave de un resultado diferente
        nonce = os.urandom(12)
        encoded_nonce = base64.b64encode(nonce).decode(
            "utf-8")  # this is send in the request
        #Additional data
        aad = aad.encode("utf-8")
        encoded_aad = base64.b64encode(aad).decode(
            "utf-8")
        text = text.encode("utf-8")
        #Se realiza el cifrado del texto con ChaCha junto nonce y add.
        cypher_text = chacha.encrypt(nonce, text, aad)
        cypher_text_encoded = base64.b64encode(cypher_text).decode("utf-8")

        # ADD LOG:
        self.log_message("End", "Encryption", len(key)*8,
                         "ChaCha20Poly1305", cypher_text_encoded)

        return [cypher_text_encoded, encoded_nonce, encoded_aad]
        # cipher_text = Fernet(key).encrypt(text.encode("utf-8"))
        # return cipher_text.decode("utf-8")

    #Método de desencriptado simetrico
    def symmetric_decrypt(self, cypher_text_encoded, key, encoded_nonce, encoded_aad):
        # ADD LOG:
        self.log_message("Starting", "Decryption", len(
            key)*8, "ChaCha20Poly1305", cypher_text_encoded)

        #Hacemos el chacha de la key
        key = base64.b64decode(key.encode("utf-8"))
        chacha = ChaCha20Poly1305(key)
        #Desciframos el nonce y el add
        nonce = base64.b64decode(encoded_nonce.encode("utf-8"))
        aad = base64.b64decode(encoded_aad.encode("utf-8"))
        #Pasamos el texto cifrado al texto original
        cypher_text = base64.b64decode(cypher_text_encoded.encode("utf-8"))
        original_text = chacha.decrypt(nonce, cypher_text, aad)
        original_text = original_text.decode("utf-8")
        # ADD LOG:
        self.log_message("End", "Decryption", len(key)*8,
                         "ChaCha20Poly1305", original_text)

        return original_text

    #Método de encrptación con clave pública
    def asymmetric_encrypt_with_external_public_key(self, key_pem, text):
        # Encrypting using the public key with (PKCS1v15 padding)
        # ADD LOG:
        self.log_message("Starting", "Asymmetric Encryption",
                         2048, "RSA", text)

        #Carga la clave pública desde la cadena en formato PEM
        public_key = serialization.load_pem_public_key(
            key_pem.encode('utf-8')
        )

        #Usa la clave pública para cifrar el texto, siendo PKCS1v15 el esquema de relleno para el cifrado, haciendo el proceso más seguro
        cipher_text = public_key.encrypt(
            text.encode(),
            padding.PKCS1v15()
        )
        result = base64.b64encode(cipher_text).decode('utf-8')

        # ADD LOG:

        self.log_message("End", "Asymmetric Encryption", 2048,
                         "RSA", result)

        return result

    #Método de descifrado asimétrico
    def asymmetric_decrypt(self, cipher_text):
        # ADD LOG:
        self.log_message("Starting", "Asymmetric Decryption",
                         2048, "RSA", cipher_text)

        print(cipher_text)
        # Decrypting using the private key (PKCS1v15 padding)
        cipher_text = base64.b64decode(cipher_text)
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

    #Método que tiene como objetivo exportar la clave pública para que sea transmitida o almacenada.
    def export_public_key(self):
        # Export in PEM format
        public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.log_message("other", f"Exporting public key", None,
                         None, f"result: {public_key} of lenght {len(public_key)*8}")
        return public_key

    #Método que cifra el cuerpo de datos
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

    #Método para descifrar el cuerpo 
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

    #Método que se encarga de hashear una contraseña junto a un salt
    def hash_salt(self, password, salt):

        if salt is None:
            salt = os.urandom(32)
        else:
            salt = base64.b64decode(salt)
        salt_base64 = base64.b64encode(salt).decode('utf-8')
        #Crea un nuevo objeto de hash utilizando el algoritmo SHA-256 y le añade la contraseña y el salt
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode('utf-8'))
        digest.update(salt)
        #Finaliza el proceso de hash y genera el hash resultante
        password_hashed = digest.finalize()
        password_hashed_base64 = base64.b64encode(
            password_hashed).decode('utf-8')

        self.log_message("other", f"Password hashed", None,
                         None, f"result: {password_hashed_base64}")
        return password_hashed_base64, salt_base64
