import random
import string

def create_input_message():
    username = input("Introduce tu nombre: ")
    password = input("Introduce tu contraseña: ")
    message = input("Introduce el mensaje: ")
    return username, password, message

def create_random_message():
        def random_string(length):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))




    username = random_string(8)
    password = random_string(8)
    message = random_string(16)
    return username, password, message