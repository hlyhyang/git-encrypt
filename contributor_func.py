import cryptography
# General Notes: Fernet is part of cryptography package for high level tools,
#                hazmat is for low level primitives
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pathlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def generate_asymmetric_private_keys():
    ''' For regular users: Create private/public keys for asymmetric encryption'''
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
        )
    return private_key


def serialize_asymmetric_keys(private_key, password, username):
    '''Serializes keys and writes them to a .pem file. Note: I should add an option to define filename etc.'''
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    password = bytes(password, 'utf-8')
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    dirname = str(pathlib.Path().absolute())
    print('Path of public key is ' + dirname + '/public_asymmetric_key.pem')
    with open((dirname + "/public_asymmetric_key_" + username + ".pem"), "wb") as public_key_file:
        public_key_file.write(public_pem)
    dirname = input("Enter a path to save your private key: ")
    with open((dirname + "/private_asymmetric_key_" + username + ".pem"), "wb") as private_key_file:
        private_key_file.write(private_pem)

def decrypt_symmetric_key():
    # Raises InvalidSignature if verification fails
    username = input("Enter the username you chose when setting up asymmetric keys: ")
    # Import public signature key
    dirname = str(pathlib.Path().absolute())
    sigpublickeyfilepath = (dirname +"/sig_public_key.pem")
    with open(sigpublickeyfilepath, "rb") as sig_public_key_file:
        sig_public_key = serialization.load_pem_public_key(
            sig_public_key_file.read(),
            backend=default_backend()
        )
    # Import encrypted symmetric key
    with open((dirname + "/encrypted_symmetric_key_" + username + ".pem"), "rb") as symmetric_key_file:
        ciphertext = symmetric_key_file.read()
    # Import asymmetric private key
    password = input("Enter the password for your locally stored asymmetric private key: ")
    password = bytes(password, 'utf-8')
    #privatekeyfilepath = (dirname +"/user"+ "/private_asymmetric_key_" + username + ".pem")
    privatekeyfilepath = input("Enter your private key path: ")
    with open(privatekeyfilepath, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=password,
            backend=default_backend()
        )
    # Import signature
    with open((dirname + "/encrypted_symmetric_key_signature_" + username + ".pem"), "rb") as signature_file:
        signature = signature_file.read()
    plaintext_symmetric_key = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(plaintext_symmetric_key)
    print("signature")
    print(signature)
    # Verify signature
    sig_public_key.verify(signature, ciphertext)
    # Write unencrypted symmetric key to local file
    dirname = input("enter a path to store unencrypted symmetric key locally")
    with open((dirname + "/local_symmetric_key_" + username + ".pem"), "wb") as user_local_symmetric_key_file:
        user_local_symmetric_key_file.write(plaintext_symmetric_key)


def decrypt_code_file():
    '''Decrypts the contents of an encrypted file'''
    username = input("Enter your username: ")
    encrypted_file_name = input("Enter the name of the encrytpted file (without the .[extention]): ")
    encrypted_file_ext = input("Enter the file extention of the encrytpted file (without the period): ")
    # Import locally stored symmetric key
    dirname = str(pathlib.Path().absolute())
    #symmetrickeyfilepath = (dirname + "/local_symmetric_key_" + username + ".pem")
    symmetrickeyfilepath =input("Enter local unencrypted symmetric key file path: ")
    with open(symmetrickeyfilepath, "rb") as symmetric_key_file:
        symmetric_key = symmetric_key_file.read()
    # Import contents of encrypted file
    encrypted_file_path = (dirname +"/" + encrypted_file_name + "." + encrypted_file_ext)
    with open(encrypted_file_path, "rb") as encrypted_file:
        encrypted_file_contents = encrypted_file.read()
    # Decrypt the contents of the encrypted file
    f = Fernet(symmetric_key)
    unencrypted_file_contents = f.decrypt(encrypted_file_contents).decode("utf-8")
    # Write unencrypted code to local file
    dirname =input("Enter the path you want to store unencrypted file: ")
    unencrypted_file_path = (dirname +'/'+ encrypted_file_name + "_unencrypted." + encrypted_file_ext)
    with open(unencrypted_file_path, "w") as user_decrypted_code_file:
        user_decrypted_code_file.write(unencrypted_file_contents)