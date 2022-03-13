from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from typing import cast
import json
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

en = public_key.encrypt(b'123123123',pads)
print("en    ",en)
res = json.dumps(en.decode('latin1'))
print("res    ",res)
res = json.loads(res)
print("res    ",res)
res = bytes(res,'latin1')
print(type(res))
print(res==en)
private_key.decrypt(res,pads)