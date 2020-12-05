import os
import cryptography
# General Notes: Fernet is part of cryptography package for high level tools,
#                hazmat is for low level primitives
import pathlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import contributor_func as user

def user_func():
    admin = input("Enter the username of the person whose project you want to join: ")
    proj_name = input("Enter the project name: ")
    parent_dir = os.getcwd()
    proj_name = admin +"-"+proj_name
    admin_proj_dir =os.path.join(parent_dir,proj_name)
    os.chdir(admin_proj_dir)

    if(input("generate asymmetric key? Enter y to generate, Enter any other to use existing key ")=='y'):
        # For regular users: Create private/public keys for asymmetric encryption
        private_key = user.generate_asymmetric_private_keys()
        #                    Serialize and write keys to file.
        password = input("Enter a password for protecting locally stored private key for asymmetric scheme: ")
        username = input("Enter a unique username to use for filenames: ")
        user.serialize_asymmetric_keys(private_key, password, username)
    else:
        if(input("get unencrypted symmetric key? press y else press any key to continue ")=='y'):
            user.decrypt_symmetric_key()
    user.decrypt_code_file()
