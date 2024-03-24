from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

IP_SERVER = u'localhost'

def generate_self_signed_cert():
    # Generar una clave RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Crear un certificado autofirmado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, IP_SERVER)
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, SHA256(), default_backend())

    # Convertir la clave privada y el certificado a formato PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

    return private_key_pem, cert_pem

# Generar clave privada y certificado autofirmado
private_key, cert = generate_self_signed_cert()

# Guardar la clave privada y el certificado en archivos
with open("server-key.pem", "wb") as key_file:
    key_file.write(private_key)

with open("server-cert.pem", "wb") as cert_file:
    cert_file.write(cert)

print("Clave privada y certificado autofirmado generados con éxito.")

