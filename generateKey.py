from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from header import *

for i in range(CLIENTNUM):
    privateKeyName = "privateKey"+str(i)+".pem"
    publicKeyName = "publicKey"+str(i)+".pem"
    privateKey = rsa.generate_private_key(65537, 2048)
    pem = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    f = open(privateKeyName, "wb")
    f.write(pem)
    f.close()
    publicKey = privateKey.public_key()
    pem = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    f = open(publicKeyName, "wb")
    f.write(pem)
    f.close()