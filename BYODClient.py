import socket
import message
import json
import ssl

HOST = '192.168.43.187'
PORT = 7070

# Ruta al archivo de certificado del servidor
CERTFILE = 'server-cert.pem'

def verify_cert(cert, hostname):
    # Verificar si la dirección IP está en el certificado
    for sub in cert['subject']:
        if sub[0][0] == 'commonName':
            if sub[0][1] == hostname:
                return True
    return False

def main():
    try:
        # Crear un socket TCP/IP
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Crear un contexto SSL/TLS y forzar el uso de TLS 1.3
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3

        # Configurar la lista de Cipher Suites
        cipher_suites = [
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
        ]

        # Configurar el contexto SSL/TLS
        # ssl_context.set_ciphers(':'.join(cipher_suites))
        ssl_context.load_verify_locations(CERTFILE)  # Cargar el certificado del servidor
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.check_hostname = False

        # Utilizar SSL/TLS para el socket
        ssl_socket = ssl_context.wrap_socket(client_socket, server_hostname=HOST)

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

    except Exception as e:
        print("Error:", e)

    finally:
        # Cerrar la conexión
        ssl_socket.close()

if __name__ == "__main__":
    main()




