from ftplib import print_line
from sys import argv
from Crypto.PublicKey import RSA

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa as rsa2
from cryptography.hazmat.primitives import serialization

def generate():
    keys = RSA.generate(2048, None,None)

    #print_line(str(keys.publickey()))
    #print_line(str(keys.exportKey('PEM')))
    #print_line(str(keys.has_private()))

    #---------------------



    #Writes a key in PEM format to disk
    f = open('mykey.pem', 'wb')
    pk= keys.exportKey('PEM')
    RsaKey publick = keys.publickey()
    print(publick)
    f.write(pk)

    f.close()

    #Loads the key from disk
    with open("mykey.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    #private_key = rsa2.generate_private_key(
    #    public_exponent=65537,
    #    key_size=2048,
    #    backend=default_backend())
    private_numbers = private_key.private_numbers()
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    n = public_numbers.n
    e = public_numbers.e
    d = private_numbers.d
    print("Public:"+ str(public_key))
    print("Private:" + str(private_key))
    print("n:" + str(n))
    print("e:" + str(e))
    print("d:" + str(d))


    #print_line(str(keys.keydata.g)
    return 1

if __name__ == "__main__":
    if len(argv) < 2:
        print ("USAGE: python vrf_marcos.py [alpha]")
    else:
        print_line("Marcos")
        print_line(generate())
        exit(1)