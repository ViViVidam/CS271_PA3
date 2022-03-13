from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
pads = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
tmp = b'1232112341324adsfasfasdbfnjhasdkfhsakjhewkqrwqer35asdfasdfasdfasdfasdf41325asdfjaskdfuyguwkerbwqyueirygadfbhsadiervbhwuerbhuasdfbhsakdfbashjkdfbhsjkdfbashdfjkasbdfhjkasbdfhajksbdfhajksdfbhasjkdfbashjdkfbashjkdfbasdf'


def encryptAndChunk(key, data: bytes):
    i = 0
    packet = []
    while i < len(data):
        packet.append(key.encrypt(data[i:(i + 190)], pads))
        i += 190
    return packet


def decryptAndConnect(key, packet: [bytes]):
    decryption = []
    for item in packet:
        tmp = key.decrypt(item, pads)
        decryption.append(tmp)
    return b"".join(decryption)

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=512,
    backend=default_backend()
)
private_key2 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)
public_key = private_key2.public_key()
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
packet = encryptAndChunk(public_key,pem)


print(len(pem))

string = decryptAndConnect(private_key2,packet)
print(string)