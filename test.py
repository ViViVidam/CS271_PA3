from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import sys
pads = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())


def encryptAndChunk(key, data: bytes):
    i = 0
    total = 0
    packet = []
    while i < len(data):
        tmp = key.encrypt(data[i:(i + 190)], pads)
        tmp = tmp.decode('latin1')
        total +=sys.getsizeof(tmp)
        packet.append(tmp)
        i += 190
    print(total)
    return packet


def decryptAndConnect(key, packet: [bytes]):
    decryption = []
    for item in packet:
        tmp = item.encode('latin1')
        tmp = key.decrypt(tmp, pads)
        decryption.append(tmp)
    return b"".join(decryption)

packet = encryptAndChunk(public_key,pem)
print(sys.getsizeof(packet),sys.getsizeof(pem))