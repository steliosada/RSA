from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


def generate_keys():
    # RSA modulus length must be a multiple of 256 and >= 1024
    modulus_length = 256*4 # use larger value in production
    privatekey = RSA.generate(modulus_length, Random.new().read)
    publickey = privatekey.publickey()
    return privatekey, publickey

def encrypt_message(a_message , publickey):
    encryptor = PKCS1_OAEP.new(publickey)
    encrypted_msg =  encryptor.encrypt(a_message)
    return encrypted_msg

def decrypt_message(encrypted_msg, privatekey):
    decryptor = PKCS1_OAEP.new(privatekey)
    decrypted_msg = decryptor.decrypt(encrypted_msg)
    decrypted_msg=decrypted_msg.decode("utf-8")
    return decrypted_msg

# MAIN

a_message = input("Give Message for encryption: ")
a_message = bytes(a_message, encoding= 'utf-8')

privatekey , publickey = generate_keys() 
encrypted_msg = encrypt_message(a_message , publickey)
decrypted_msg = decrypt_message(encrypted_msg, privatekey)
a_message=a_message.decode("utf-8")
print ("%s - (%d)" % (privatekey.exportKey() , len(privatekey.exportKey())))
print ("%s - (%d)" % (publickey.exportKey() , len(publickey.exportKey())))
print ("Original content: %s " % (a_message))
print ("Encrypted message: %s " % (encrypted_msg, ))
print ("Decrypted message: %s " % (decrypted_msg,))
input("Press any key to exit.")