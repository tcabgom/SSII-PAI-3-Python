from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import datetime

# Generar una clave privada RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)


subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Sevilla"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Sevilla"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"John"),
    x509.NameAttribute(NameOID.SURNAME, u"Doe"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"My Organizational Unit"),
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
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).sign(private_key, hashes.SHA256(), default_backend())


private_key_pem = private_key.private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
)
cert_pem = cert.public_bytes(Encoding.PEM)


with open("server-key.pem", "wb") as private_key_file:
    private_key_file.write(private_key_pem)

with open("server-cert.pem", "wb") as cert_file:
    cert_file.write(cert_pem)

print("Clave privada y certificado autofirmado generados con éxito.")

