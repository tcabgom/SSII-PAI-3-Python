import json
import logging
import socket
import threading
from OpenSSL import SSL
import sqlite3
from users import USERS

HOST = 'localhost'
PORT = 7070

# Rutas a los archivos de clave privada y certificado del servidor
KEYFILE = 'server-key.pem'
CERTFILE = 'server-cert.pem'

logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def handle_client(connection_socket, address):
    try:
        logging.info("Conexión aceptada desde: %s", address)

        data = connection_socket.recv(1024).decode()
        client_data = json.loads(data)
        username = client_data['username']
        password = client_data['password']
        message = client_data['message']

        # Autenticar al usuario
        auth_result = authenticate_user(connection_socket, username, password)
        if not auth_result:
            logging.warning("Autenticación fallida de %s", address)
            return
        
        logging.info("Mensaje recibido del cliente: %s", message)
        store_secret_message(connection_socket, message)

    except Exception as e:
        logging.error("Error: %s", e)

    finally:
        # Cerrar la conexión
        connection_socket.close()
        logging.info("Conexión cerrada con %s", address)

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
        logging.info("Mensaje", message, "almacenado correctamente")

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

        logging.info(f"Servidor escuchando en {HOST}:{PORT}...")

        while True:
            # Aceptar conexiones entrantes
            connection_socket, addr = server_socket.accept()

            # Configurar el contexto SSL/TLS con OpenSSL
            ctx = SSL.Context(SSL.TLS_METHOD)
            ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
            ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
            ctx.set_max_proto_version(SSL.TLS1_3_VERSION)

            #ctx.set_cipher_list(b'AES128-GCM-SHA256')

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
        logging.error("Error: %s", e)

    finally:
        # Cerrar el socket del servidor
        logging.shutdown("Cerrando el servidor...")
        server_socket.close()


if __name__ == "__main__":
    main()
