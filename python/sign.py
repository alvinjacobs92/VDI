import random
import math
import rsa
import sys
import string

def sign (fileName, privKey):
#opening the file
    with open (fileName,"rb") as f:
        message = f.read()
#signing
    signature = rsa.sign(message,privKey,"SHA-256")
    return signature



#signature = sign("./uploads/"+str(sys.argv[1],str(sys.argv[2]))
#+str(sys.argv[1])
#str(sys.argv[2])



#leer private key de texto a variable
privKey = rsa.PrivateKey.load_pkcs1(sys.argv[2])

signature = sign("uploads/"+str(sys.argv[1]),privKey)

with open ("uploads/signatures/"+str(sys.argv[1]), "wb") as f:
    f.write(signature)

#print("./uploads/signatures/"+str(sys.argv[1]))

#print("Result:",sign("./uploads/"+ str(sys.argv[1]),privKey))
#print("Signed correctly: ", str(sys.argv[1]),str(sys.argv[2]))