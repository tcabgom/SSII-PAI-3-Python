import socket
import message
import json
import time
import threading
from OpenSSL import SSL

HOST = 'localhost'  # Dirección IP del servidor
PORT = 7070

# Ruta al archivo de certificado del servidor
CERTFILE = 'server-cert.pem'

# Variable global para almacenar el tiempo total acumulado
total_elapsed_time = 0

# Mutex para asegurar la escritura en el archivo de registro
mutex = threading.Lock()

def client_thread(thread_id):
    global total_elapsed_time
    try:
        # Crear un socket TCP/IP
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Crear un contexto SSL/TLS con OpenSSL
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
        
        # Cargar el certificado del servidor
        ctx.load_verify_locations(CERTFILE)
        ctx.set_verify(SSL.VERIFY_PEER, lambda x, y, z, a, b: True)

        # Utilizar SSL/TLS para el socket
        ssl_socket = SSL.Connection(ctx, client_socket)

        # Conectar al servidor
        ssl_socket.connect((HOST, PORT))

        # Crear objeto JSON con los datos de usuario y el mensaje
        json_data = message.create_random_message()

        # Enviar datos al servidor
        ssl_socket.sendall(json_data.encode())

        # Recibir respuesta del servidor
        response = ssl_socket.recv(1024)
        print(f"Respuesta del servidor para hilo {thread_id}:", response.decode())
        
        if ssl_socket:
            ssl_socket.close()

    except Exception as e:
        print("Error:", e)

def main():
    global total_elapsed_time
    try:
        start_time = time.time()
        threads = []
        for i in range(1, 301):
            thread = threading.Thread(target=client_thread, args=(i,))
            threads.append(thread)
            thread.start()
            if i % 50 == 0:
                with mutex:
                    elapsed_time = time.time() - start_time
                    total_elapsed_time += elapsed_time
                    print(f"{i} conexiones completadas. Tiempo total acumulado: {total_elapsed_time:.2f} segundos.")
                    with open("log.txt", "a") as f:
                        f.write(f"{i} conexiones completadas. Tiempo total acumulado: {total_elapsed_time:.2f} segundos.\n")
                    start_time = time.time()

        for thread in threads:
            thread.join()

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
