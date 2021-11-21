import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as padd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pickle
import io


def generate_keys(path_symmetric_key: str, path_public_key: str, path_secret_key: str):
    symmetric_key = os.urandom(16)
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    with open(path_public_key, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(path_secret_key, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    c_symmetric_key = public_key.encrypt(symmetric_key,
                                         padd.OAEP(mgf=padd.MGF1(algorithm=hashes.SHA256()),
                                                   algorithm=hashes.SHA256(),
                                                   label=None))
    with open(path_symmetric_key, 'wb') as key_file:
        key_file.write(c_symmetric_key)


generate_keys('symmetric_key.txt', 'public.pem', 'private.pem')


def encryption_data(path_text: str, path_secret_key, path_symmetric_key: str, path_encrypted_text):
    with open(path_symmetric_key, mode='rb') as key_file:
        symmetric_key = key_file.read()
    with open(path_secret_key, 'rb') as pem_in:
        private_bytes = pem_in.read()
        private_key = load_pem_private_key(private_bytes, password=None, )
    dc_key = private_key.decrypt(symmetric_key,
                                  padd.OAEP(mgf=padd.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                            label=None))
    f = open(path_text, 'r')
    data = f.read()
    f.close()
    padder = padding.ANSIX923(8).padder()
    data = bytes(data, 'UTF-8')
    padded_text = padder.update(data) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SM4(dc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_data = encryptor.update(padded_text)
    setting = {}
    setting['text'] = c_data
    setting['iv'] = iv
    f = open(path_encrypted_text, "wb")
    pickle.dump(setting, f)
    f.close()


encryption_data('text.txt', 'private.pem', 'symmetric_key.txt', 'c_text.txt')


def decryption_data(path_secret_key, path_symmetric_key: str, path_encrypted_text, path_decrypted_text):
    with open(path_symmetric_key, mode='rb') as key_file:
        symmetric_key = key_file.read()
    with open(path_secret_key, 'rb') as pem_in:
        private_bytes = pem_in.read()
        private_key = load_pem_private_key(private_bytes, password=None, )
    dc_key = private_key.decrypt(symmetric_key,
                                  padd.OAEP(mgf=padd.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                            label=None))
    f = open(path_encrypted_text, "rb")
    data = pickle.load(f)
    f.close()
    text_to_decrypt = data['text']
    iv = data["iv"]
    cipher = Cipher(algorithms.SM4(dc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dc_data = decryptor.update(text_to_decrypt) + decryptor.finalize()
    unpadder = padding.ANSIX923(8).unpadder()
    unpadded_dc_data = unpadder.update(dc_data)
    dc_dataa = unpadded_dc_data.decode("UTF-8")
    f = io.open("d_text.txt", mode="w", encoding="utf-8")
    f.write(str(dc_dataa))


decryption_data('private.pem', 'symmetric_key.txt', 'c_text.txt', 'd_text.txt')
