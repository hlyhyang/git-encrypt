import os
import cryptography
import pathlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import admin_gen_keys as admin

username =input("Enter your user name: ")
new_dir = input("Create a new project folder? Enter Y to create or press other keys to enter exisitng project folder ")
if(new_dir =="Y" or new_dir=="y"):
    proj_name = input("Enter your project name: ")
    proj_dir = admin.create_proj_folder(username, proj_name)
else:
    proj_name = input("Enter your existing project folder name: ")
    parent_dir = os.getcwd()
    proj_name = username +"-"+proj_name
    proj_dir =os.path.join(parent_dir,proj_name)
    os.chdir(proj_dir)

password = input("Enter a password to encrypt your locally stored private keys: ")
symmetric_key = admin.generate_symmetric_key()
admin.create_signature_keys(password)
admin.encrypt_code_file()

filename = input("Enter the user name of the chosen user: ")
dirname = str(pathlib.Path().absolute())
keyfilepath = (dirname + "/public_asymmetric_key_" + filename + ".pem")
ciphertextfilepath = (dirname +"/encrypted_symmetric_key_" + filename + ".pem")
signaturefilepath = (dirname + "/encrypted_symmetric_key_signature_" + filename + ".pem")
password = input("Enter the password for your private key for signatures: ")
# For Administrator (Alice): Encrypt the symmetric key and write it to a file for user
ciphertext, signature = admin.publicly_encrypt_symmetric_key(keyfilepath, ciphertextfilepath, signaturefilepath, password)

print('ciphertext is: ')
print(ciphertext)
print('signature is: ')
print(signature)
