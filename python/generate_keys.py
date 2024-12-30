import random
import math
import rsa
import sys


def generate_keys ():
    pubKey,privKey = rsa.newkeys(2048)

    with open ("public.pem","wb") as f:
        f.write(pubKey.save_pkcs1("PEM"))
    with open ("private.pem","wb") as f:
        f.write(privKey.save_pkcs1("PEM"))

#Generar keys:
generate_keys()

