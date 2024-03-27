import socket
import message
import json
from OpenSSL import SSL

HOST = 'localhost'  # Dirección IP del servidor
PORT = 7070

# Ruta al archivo de certificado del servidor
CERTFILE = 'server-cert.pem'

def main():
    try:
        # Crear un socket TCP/IP
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Crear un contexto SSL/TLS con OpenSSL
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
        
        # Seleccionar el algoritmo de cifrado y el hash si se desea
        #ctx.set_cipher_list(b'AES128-GCM-SHA256')

        # Cargar el certificado del servidor
        ctx.load_verify_locations(CERTFILE)
        ctx.set_verify(SSL.VERIFY_PEER, lambda x, y, z, a, b: True)

        # Utilizar SSL/TLS para el socket
        ssl_socket = SSL.Connection(ctx, client_socket)

        # Conectar al servidor
        ssl_socket.connect((HOST, PORT))
        print(f"Conectado al servidor {HOST}:{PORT}")

        # Crear objeto JSON con los datos de usuario y el mensaje
        json_data = message.create_input_message()

        # Enviar datos al servidor
        ssl_socket.sendall(json_data.encode())

        # Recibir respuesta del servidor
        response = ssl_socket.recv(1024)
        print("Respuesta del servidor:", response.decode())
        
        if ssl_socket:
            ssl_socket.close()

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()