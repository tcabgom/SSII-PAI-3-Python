import json
import random
import string
from users import USERS

def create_input_message():
    data = {
        "username": input("Introduce tu nombre: ")[:50],
        "password": input("Introduce tu contraseña: ")[:50],
        "message": input("Introduce el mensaje: ")[:50]
    }
    json_data = json.dumps(data)
    return json_data


def random_string(length):
    
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def create_random_message():
 
    username, password = random.choice(list(USERS.items()))
    message = random_string(16)
    json_data = json.dumps({"username": username, "password": password, "message": message})
    return json_data
