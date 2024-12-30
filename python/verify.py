import random
import math
import rsa
import sys
import os

def verify (fileName, pubKey, signature):

#Abrir archivo firmado para verificar
    with open (fileName,"rb") as f:
        message = f.read()
    try:
        bool = rsa.verify(message,signature,pubKey)
    except rsa.pkcs1.VerificationError:
        bool = 0
    
    if(bool=="SHA-256"):
        bool=1
    else:
        bool=0
    return bool

def deleteFile (filepath):
    if os.path.exists(filepath):
        os.remove(filepath)



#req.files.doc[0].originalname,req.files.doc[0].filename,req.files.sig[0].filename,req.body.body
#sys.argv[1] = req.files.doc[0].originalname (the original title of the document)
#sys.argv[2] = req.files.doc[0].filename (the address we will use to find the new upload. not clean i know...)
#sys.argv[3] = req.files.sig[0].filename (the address we will use to find the signature in the files)
#sys.argv[4] = req.body.body (the pubkey as text, needs to be converted to be used.)

#sys.argv[1] = req.files.doc[0].originalname (the original title of the document) no es necesario... se


#test:
originalDocLoc="uploads/"+sys.argv[2]

#Abro la firma
sigLocation="uploads/"+sys.argv[3]
with open (sigLocation,"rb") as f:
    signature = f.read()


#Public Key del firmante:
pubKey = rsa.PublicKey.load_pkcs1(sys.argv[4])

#Verificador responde booleano
bool = verify (originalDocLoc, pubKey, signature)

if(bool):
    print("POSITIVE - signature validated")
else:
    print("NEGATIVE - signature did not verify")

