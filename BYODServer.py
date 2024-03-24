import json
import socket
import threading
from OpenSSL import SSL
import sqlite3

HOST = 'localhost'
PORT = 7070

# Usuarios y contraseñas permitidos
USERS = {
    'usuario1': 'password1',
    'usuario2': 'password2'
}

# Rutas a los archivos de clave privada y certificado del servidor
KEYFILE = 'server-key.pem'
CERTFILE = 'server-cert.pem'

def handle_client(connection_socket, address):
    try:
        print("Conexión aceptada desde:", address)

        data = connection_socket.recv(1024).decode()
        client_data = json.loads(data)
        username = client_data['username']
        password = client_data['password']
        message = client_data['message']

        # Autenticar al usuario
        auth_result = authenticate_user(connection_socket, username, password)
        if not auth_result:
            print("Autenticación fallida."+str(address))
            return
        
        print("Mensaje recibido del cliente:", message)
        store_secret_message(connection_socket, message)

    except Exception as e:
        print("Error:", e)

    finally:
        # Cerrar la conexión
        connection_socket.close()

def authenticate_user(connection_socket, username, password):
    # Verificar nombre de usuario y contraseña
    if username in USERS and USERS[username] == password:
        return True
    else:
        connection_socket.sendall(b"Autenticacion fallida.")
        return False

def store_secret_message(connection_socket, message):
    try:
        # Conexión a la base de datos
        conn = sqlite3.connect('messages.db')
        cursor = conn.cursor()

        # Crear la tabla si no existe
        cursor.execute('''CREATE TABLE IF NOT EXISTS secret_messages 
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, message TEXT)''')

        # Insertar el mensaje en la tabla
        cursor.execute("INSERT INTO secret_messages (message) VALUES (?)", (message,))
        conn.commit()

        # Cerrar la conexión a la base de datos
        conn.close()

        # Enviar confirmación al cliente
        connection_socket.sendall(b"Mensaje almacenado correctamente.")
        
    except Exception as e:
        print("Error al almacenar el mensaje:", e)
        connection_socket.sendall(b"Error al almacenar el mensaje.")

def main():
    try:
        # Crear un socket TCP/IP
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Enlazar el socket al host y puerto
        server_socket.bind((HOST, PORT))

        # Escuchar conexiones entrantes
        server_socket.listen()

        print(f"Servidor escuchando en {HOST}:{PORT}...")

        while True:
            # Aceptar conexiones entrantes
            connection_socket, addr = server_socket.accept()

            # Configurar el contexto SSL/TLS con OpenSSL
            ctx = SSL.Context(SSL.TLS_METHOD)
            ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
            ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
            ctx.set_max_proto_version(SSL.TLS1_3_VERSION)

            ctx.set_cipher_list(b'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-CCM-SHA256')

            # Cargar el certificado del servidor
            ctx.use_certificate_file(CERTFILE)

            # Cargar la clave privada del servidor
            ctx.use_privatekey_file(KEYFILE)

            # Utilizar SSL/TLS para el socket
            ssl_socket = SSL.Connection(ctx, connection_socket)
            ssl_socket.set_accept_state()

            # Manejar el cliente en un hilo separado
            client_thread = threading.Thread(target=handle_client, args=(ssl_socket, addr))
            client_thread.start()

    except Exception as e:
        print("Error:", e)

    finally:
        # Cerrar el socket del servidor
        server_socket.close()

if __name__ == "__main__":
    main()





'''
import json
import socket
import ssl
import threading
from ssl import PROTOCOL_TLS_SERVER

HOST = ''
PORT = 7070

# Usuarios y contraseñas permitidos
USERS = {
    'usuario1': 'password1',
    'usuario2': 'password2'
}

# Rutas a los archivos de clave privada y certificado del servidor
KEYFILE = 'server-key.pem'
CERTFILE = 'server-cert.pem'

def handle_client(connection_socket, address):
    try:
        print("Conexión aceptada desde:", address)

        data = connection_socket.recv(1024).decode()
        client_data = json.loads(data)
        username = client_data['username']
        password = client_data['password']
        message = client_data['message']

        # Autenticar al usuario
        auth_result = authenticate_user(connection_socket, username, password)
        if not auth_result:
            return
        
        print("Mensaje recibido del cliente:", message)
        store_secret_message(connection_socket)

    except Exception as e:
        print("Error:", e)

    finally:
        # Cerrar la conexión
        connection_socket.close()

def authenticate_user(connection_socket, username, password):
    # Recibir nombre de usuario y contraseña del cliente

    # Verificar nombre de usuario y contraseña
    if username in USERS and USERS[username] == password:
        return True
    else:
        connection_socket.sendall(b"Autenticacion fallida.")
        return False

def store_secret_message(connection_socket):
    # Almacenar el mensaje secreto
    connection_socket.sendall(b"Mensaje almacenado correctamente.")

def main():
    # Configuración del host y puerto del servidor


    try:
        # Crear un socket TCP/IP
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Enlazar el socket al host y puerto
        server_socket.bind((HOST, PORT))

        # Escuchar conexiones entrantes
        server_socket.listen()

        print(f"Servidor escuchando en {HOST}:{PORT}...")

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Configurar la lista de Cipher Suites
        cipher_suites = [
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_128_CCM_SHA256",
                "TLS_AES_128_CCM_8_SHA256"
        ]

        # Configurar el contexto SSL/TLS
        #ssl_context.set_ciphers(':'.join(cipher_suites))
        ssl_context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)

        # Forzar el uso de TLS 1.3
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        while True:
            # Aceptar conexiones entrantes
            connection_socket, addr = server_socket.accept()

            # Utilizar SSL/TLS para el socket
            ssl_socket = ssl_context.wrap_socket(connection_socket, server_side=True)

            # Manejar el cliente en un hilo separado
            client_thread = threading.Thread(target=handle_client, args=(ssl_socket, addr))
            client_thread.start()

    except Exception as e:
        print("Error:", e)

    finally:
        # Cerrar el socket del servidor
        server_socket.close()

if __name__ == "__main__":
    main()

'''