import json
import random
import string

def create_input_message():
    data = {
        "username": input("Introduce tu nombre: ")[:50],
        "password": input("Introduce tu contraseña: ")[:50],
        "message": input("Introduce el mensaje: ")[:50]
    }
    json_data = json.dumps(data)
    return json_data


def create_random_message():
    
    def random_string(length):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    username = random_string(8)
    password = random_string(8)
    message = random_string(16)
    return username, password, message