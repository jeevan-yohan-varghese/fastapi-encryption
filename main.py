import uvicorn
from fastapi import FastAPI,Request

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from dotenv import load_dotenv
import os
load_dotenv(".env")
from fastapi.middleware.cors import CORSMiddleware

app=FastAPI()
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from schema import CryptoRequest


origins = [
    "http://localhost:3000",
    "https://cognosco.vercel.app",
    "https://railway-gilt.vercel.app",
    "https://cognoscotvm.azurewebsites.net",
    "http://localhost:8000",
    "104.196.232.237:443"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# AES encryption function
def encrypt_AES(key, iv, plaintext):
    # Create a Cipher object with AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Create an encryptor object from the Cipher
    encryptor = cipher.encryptor()
    
    # Apply padding to the plaintext
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext

# AES decryption function
def decrypt_AES(key, iv, ciphertext):
    # Create a Cipher object with AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Create a decryptor object from the Cipher
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding from the decrypted plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
    
    return plaintext


@app.get("/")
async def root():
    return {"message":"Hello World"}



@app.post("/encrypt")
async def encrypt(request:Request):
    json=await request.json()
    
    try:

        cipher = AES.new(os.environ['KEY'].encode(), AES.MODE_ECB)
        padded_plaintext = pad(json['data'].encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        print(ciphertext)
        return {"cipher":ciphertext.hex()}
    except Exception as ex:
        print(str(ex))
        return {"error":str(ex)}

    
   
    

@app.post("/decrypt")
async def decrypt(request:Request):
    json=await request.json()
    cipher = AES.new(os.environ['KEY'].encode(), AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(bytes.fromhex(json['ciphertext']))
    plaintext = unpad(padded_plaintext, AES.block_size)
    print(plaintext)
    return {"plain":plaintext.decode()}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=os.getenv("PORT", default=5000), log_level="info")