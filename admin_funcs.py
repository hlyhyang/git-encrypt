import os
import cryptography
# General Notes: Fernet is part of cryptography package for high level tools,
#                hazmat is for low level primitives
import pathlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

'''generate project folder and symmetric & asymmetric keys for administrator'''
def create_proj_folder(username,proj_name):
    parent_dir = os.getcwd()
    proj_name = username +"-"+proj_name
    proj_dir =os.path.join(parent_dir,proj_name)
    os.mkdir(proj_dir)
    os.chdir(proj_dir)
    return os.getcwd()

def generate_symmetric_key():
    ''' For Administrator (Alice): Create key for symmetric encryption'''
    symmetric_key = Fernet.generate_key()
    # Write symmetric key to local file so that it can be encrypted and sent to users in the future
    dirname = str(pathlib.Path().absolute())
    keyname = input("Enter your symmetric key name: ")
    with open((dirname + "/admin_symmetric_key_"+keyname+".pem"), "wb") as local_symmetric_key_file:
        local_symmetric_key_file.write(symmetric_key)
    return symmetric_key


def create_signature_keys(password):
    '''For Administrator (Alice): Create public/private keys for signing messages.'''
    password = bytes(password, 'utf-8')
    sig_private_key = Ed25519PrivateKey.generate()
    sig_public_key = sig_private_key.public_key()
    # Get serialized, binary form of public key
    sig_public_key = sig_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Get serialized, encrypted, binary form of private key
    sig_private_key = sig_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    dirname = str(pathlib.Path().absolute())
    # Write keys to file
    with open((dirname + "/sig_public_key.pem"), "wb") as sig_public_key_file:
        sig_public_key_file.write(sig_public_key)
    with open((dirname + "/sig_private_key.pem"), "wb") as sig_private_key_file:
        sig_private_key_file.write(sig_private_key)



'''use symmetric encryption to encrypt file that administrator wants to upload'''
def encrypt_code_file():
    '''Enrypts the contents of a code file'''
    symmetric_keyname = input("Enter your symmetric_keyname: ")
    #filename =input("Enter your filename: ")
    file = input("Enter the name of a code file (without the .[extention]): ")
    file_ext = input("Enter the file extention of a code file (without the period): ")
    # Import locally stored symmetric key
    dirname = str(pathlib.Path().absolute())
    symmetrickeyfilepath = (dirname + "/admin_symmetric_key_" + symmetric_keyname + ".pem")
    with open(symmetrickeyfilepath, "rb") as symmetric_key_file:
        symmetric_key = symmetric_key_file.read()
    # Import local code file
    #filepath = (dirname + "/" + file + "." + file_ext)
    filepath = input("Enter that path: ")
    with open(filepath, "r") as code_file:
        code = code_file.read()
    # Convert to bytes
    code = bytes(code, 'utf-8')
    # Encrypt the code with the symmetric key
    f = Fernet(symmetric_key)
    ciphertext = f.encrypt(code)
    # Save encrypted file to disk
    ciphertextfilepath = (dirname + "/" + file + "_encrypted." + file_ext)
    with open(ciphertextfilepath, "wb") as encrypted_file:
        encrypted_file.write(ciphertext)

'''encrypt the symmetric key'''
def publicly_encrypt_symmetric_key(keyfilepath, ciphertextfilepath, signaturefilepath, password):
    '''For Administrator (Alice): Encrypt the symmetric key using the public key from a given user'''
    '''Using a given user's public key file, import the public key, encrypt the symmetric key and write it to file'''
    # Import public key from .pem file
    with open(keyfilepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    # Import symmetric key
    dirname = str(pathlib.Path().absolute())
    keyname = input("Enter your key name: ")
    symmetrickeyfilepath = (dirname + "/admin_symmetric_key_"+keyname+".pem")
    with open(symmetrickeyfilepath, "rb") as symmetric_key_file:
        symmetric_key = symmetric_key_file.read()
    # Encrypt symmetric Key
    ciphertext = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Import private/public signature keys
    sigpublickeyfilepath = (dirname +"/sig_public_key.pem")
    sigprivatekeyfilepath = (dirname +"/sig_private_key.pem")
    with open(sigpublickeyfilepath, "rb") as sig_public_key_file:
        sig_public_key = serialization.load_pem_public_key(
            sig_public_key_file.read(),
            backend=default_backend()
        )
    password = bytes(password, 'utf-8')
    with open(sigprivatekeyfilepath, "rb") as sig_private_key_file:
        sig_private_key = serialization.load_pem_private_key(
            sig_private_key_file.read(),
            password=password,
            backend=default_backend()
        )
    signature = sig_private_key.sign(ciphertext)
    # Write encrypted symmetric key to file
    dirname = str(pathlib.Path().absolute())
    print('Path of encrypted symmetric key is ' + ciphertextfilepath)
    with open(ciphertextfilepath, "wb") as symmetric_file:
        symmetric_file.write(ciphertext)
    with open(signaturefilepath, "wb") as symmetric_sig_file:
        symmetric_sig_file.write(signature)
    return ciphertext, signature

