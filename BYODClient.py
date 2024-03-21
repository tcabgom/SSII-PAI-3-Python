import socket
import ssl

# Ruta al archivo de certificado del servidor
CERTFILE = 'server-cert.pem'

def main():
    # Configuración del host y puerto del servidor
    HOST = 'localhost'
    PORT = 7070

    try:
        # Crear un socket TCP/IP
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Utilizar SSL/TLS para el socket
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.load_verify_locations(CERTFILE)  # Cargar el certificado del servidor
        ssl_socket = ssl_context.wrap_socket(client_socket, server_hostname=HOST)

        # Conectar al servidor
        ssl_socket.connect((HOST, PORT))
        print(f"Conectado al servidor {HOST}:{PORT}")

        # Enviar datos al servidor
        message = "Hello, server!"
        ssl_socket.sendall(message.encode())

        # Recibir respuesta del servidor
        response = ssl_socket.recv(1024)
        print("Respuesta del servidor:", response.decode())

    except Exception as e:
        print("Error:", e)

    finally:
        # Cerrar la conexión
        ssl_socket.close()

if __name__ == "__main__":
    main()


