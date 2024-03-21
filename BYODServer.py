import socket
import ssl
import threading

# Rutas a los archivos de clave privada y certificado del servidor
KEYFILE = 'server-key.pem'
CERTFILE = 'server-cert.pem'

def handle_client(connection_socket, address):
    try:
        print("Conexión aceptada desde:", address)

        # Recibir datos del cliente
        data = connection_socket.recv(1024)
        print("Mensaje recibido del cliente:", data.decode())

        # Responder al cliente
        response = "¡Hola, cliente!"
        connection_socket.sendall(response.encode())

    except Exception as e:
        print("Error:", e)

    finally:
        # Cerrar la conexión
        connection_socket.close()

def main():
    # Configuración del host y puerto del servidor
    HOST = 'localhost'
    PORT = 7070

    try:
        # Crear un socket TCP/IP
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Enlazar el socket al host y puerto
        server_socket.bind((HOST, PORT))

        # Escuchar conexiones entrantes
        server_socket.listen()

        print(f"Servidor escuchando en {HOST}:{PORT}...")

        # Cargar la clave privada y el certificado del servidor
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
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






