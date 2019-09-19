# from https://github.com/andrewlhuang/Verifiable-Random-Functions/blob/master/RSA_VRF.py
# requirements: 
#   cryptography 2.7

# import operator
# import math
# import sys

import hashlib
import base64
import binascii

from sys import argv
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization


class VrfKey(object):
    @classmethod
    def _integer_byte_size(cls, nr):
        """Returns the number of bytes necessary to store the integer n."""
        quanta, mod = divmod(cls._integer_bit_size(nr), 8)
        if mod or nr == 0:
            quanta += 1
        return quanta

    @classmethod
    def _integer_bit_size(cls, nr):
        """Returns the number of bits necessary to store the integer n."""
        if nr == 0:
            return 1
        s = 0
        while nr:
            s += 1
            nr >>= 1
        return s


class VrfPublicKey(VrfKey):
    __slots__ = ('n', 'e', 'bit_size', 'byte_size')

    def __init__(self, n, e):
        self.n = n
        self.e = e
        self.bit_size = self._integer_bit_size(n)
        self.byte_size = self._integer_byte_size(n)

    def __repr__(self):
        return '<VrfPublicKey n: %d e: %d bit_size: %d>' % (self.n, self.e, self.bit_size)

    def rsavp1(self, s):
        if not (0 <= s <= self.n-1):
            raise Exception("s not within 0 and n - 1")
        return self.rsaep(s)

    def rsaep(self, m):
        if not (0 <= m <= self.n-1):
            raise Exception("m not within 0 and n - 1")
        return pow(m, self.e, self.n)


class VrfSecretKey(VrfKey):
    __slots__ = ('n', 'd', 'bit_size', 'byte_size')

    def __init__(self, n, d):
        self.n = n
        self.d = d
        self.bit_size = self._integer_bit_size(n)
        self.byte_size = self._integer_byte_size(n)

    def __repr__(self):
        return '<VrfSecretKey n: %d d: %d bit_size: %d>' % (self.n, self.d, self.bit_size)

    def rsadp(self, c):
        if not (0 <= c <= self.n-1):
            raise Exception("c not within 0 and n - 1")
        return pow(c, self.d, self.n)

    def rsasp1(self, m):
        if not (0 <= m <= self.n-1):
            raise Exception("m not within 0 and n - 1")
        return self.rsadp(m)


class Vrf(object):

    def __init__(self, keys=None, n=None, d=None, e=None):
        # Precondition: at least one of both, keys or (n,d,e), must have value

        self.keys = keys        # type: RSA.RsaKey
        self.pem_public_key = self.get_pem_public_key()

        if keys is None and n is None and d is None and e is None:
            raise ValueError('At least one of both set of arguments, keys or (n,d,e), must have value.')

        if n and d and e:
            self.public_key = VrfPublicKey(n, e)
            self.secret_key = VrfSecretKey(n, d)
        else:
            self.public_key = self.get_public_key(pem_public_key=self.pem_public_key)
            self.secret_key = self.get_secret_key(pem_secret_key=self.keys.exportKey('PEM'))

    def get_seed_b64(self, last_hash):
        # TODO: Decidir el valor adecuado para k
        k = 20
        node_vrf_seed = self.prove(last_hash, k)

        # encode in base64
        node_vrf_seed_b64 = base64.b64encode(node_vrf_seed).decode("utf-8")
        print('DEBUG: aca antes de minar VDF generamos el seed VRF (y encodeamos en base64)!!:')
        print(node_vrf_seed_b64)

        return node_vrf_seed_b64

    @classmethod
    def create_rsa_keys(cls) -> RSA.RsaKey:
        print('Creating RSA keys...')
        return RSA.generate(2048, None)

    def prove(self, alpha, k):
        # k is the length of pi
        em = Vrf._mgf1(alpha, k - 1)
        m = Vrf.os2ip(em)
        s = self.secret_key.rsasp1(m)
        pi = Vrf._i2osp(s, k)
        return pi

    def verify(self, alpha, pi, k, miner_address):
        pi_bytes = base64.b64decode(pi)
        s = self.os2ip(pi_bytes)
        public_key = self.get_public_key(pem_public_key=miner_address)
        m = public_key.rsavp1(s)
        em = self._i2osp(m, k - 1)
        em_ = self._mgf1(alpha, k - 1)
        return em == em_

    @classmethod
    def get_secret_key(cls, pem_secret_key):
        print('DEBUG: exported PEM:')
        print(str(pem_secret_key))
        print()
        hazmat_secret_key = serialization.load_pem_private_key(pem_secret_key,
                                                               password=None,
                                                               backend=default_backend())

        # hazmat_secret_key = serialization.load_pem_private_key(key_file.read(),
        #                                                        password=None,
        #                                                        backend=default_backend())

        hazmat_public_key = hazmat_secret_key.public_key()

        secret_numbers = hazmat_secret_key.private_numbers()
        pub_numbers = hazmat_public_key.public_numbers()
        n = pub_numbers.n
        d = secret_numbers.d
        # e = pub_numbers.e
        # k = 20

        # public_key = vrf.VrfPublicKey(n, e)
        # secret_key = vrf.VrfSecretKey(n, d)

        return VrfSecretKey(n, d)

    @classmethod
    def get_public_key(cls, pem_public_key, hexlified=False) -> VrfPublicKey:
        # bytes to string
        print('DEBUG: encoding public key:')
        print(str(pem_public_key) + '\n')

        # var type: RSAPublicKey
        hazmat_public_key = serialization.load_pem_public_key(pem_public_key.encode('utf-8'),    # raw_bytes(pem)
                                                              backend=default_backend())
        if hexlified:
            return binascii.hexlify(hazmat_public_key.public_bytes)
        else:
            pub_numbers = hazmat_public_key.public_numbers()
            return VrfPublicKey(pub_numbers.n, pub_numbers.e)

    def get_pem_public_key(self):
        return self.keys.publickey().exportKey('PEM').decode("utf-8")

    @classmethod
    def proof2hash(cls, pi, hash=hashlib.sha1):
        beta = hash(pi).digest()
        return beta

    @classmethod
    def os2ip(cls, x):
        """
        Converts the byte string x representing an integer represented using the big-endian convention to an integer.
        """
        h = binascii.hexlify(x)
        return int(h, 16)

    @classmethod
    def _mgf1(cls, mgf_seed, mask_len, hash_class=hashlib.sha1):
        """
        Mask Generation Function v1 from the PKCS#1 v2.0 standard.
        mgs_seed - the seed, a byte string
        mask_len - the length of the mask to generate
        hash_class - the digest algorithm to use, default is SHA1
        Return value: a pseudo-random mask, as a byte string
        """
        h_len = hash_class().digest_size
        if mask_len > 0x10000:
            raise ValueError('mask too long')
        t = b''
        for i in range(0, cls._integer_ceil(mask_len, h_len)):
            c = cls._i2osp(i, 4)
            # t = t + hash_class( mgf_seed + c).digest()
            t = cls._concat_bytes(t, hash_class(cls._concat_bytes(mgf_seed.encode(), c)).digest())

        return t[:mask_len]

    @classmethod
    def _i2osp(cls, x, x_len):
        """
        Converts the integer x to its big-endian representation of length
        x_len.
        """
        # if x > 256**x_len:
        #     raise ValueError("integer too large")
        h = hex(x)[2:]
        if h[-1] == 'L':
            h = h[:-1]
        if len(h) & 1 == 1:
            h = '0%s' % h
        x = binascii.unhexlify(h)
        return b'\x00' * int(x_len-len(x)) + x

    @classmethod
    def _pem2hex(cls, pem):
        pem = pem.replace('\n-----END PUBLIC KEY-----\n', '')
        pem = pem.replace('-----BEGIN PUBLIC KEY-----\n', '')
        return base64.b64decode(pem).hex()

    @classmethod
    def _der2hex(cls, der):
        return binascii.hexlify(der)

    @classmethod
    def _integer_ceil(cls, a, b):
        """Return the ceil integer of a div b."""
        quanta, mod = divmod(a, b)
        if mod:
            quanta += 1
        return quanta

    @classmethod
    def _concat_bytes(cls, a, b):
        return b"".join([a, b])


if __name__ == "__main__":

    if len(argv) < 2:
        print("USAGE: python RSA_VRF.py [alpha]")
        exit(1)

    secret_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())

    secret_numbers = secret_key.private_numbers()
    public_key = secret_key.public_key()
    public_numbers = public_key.public_numbers()
    n = public_numbers.n
    e = public_numbers.e
    d = secret_numbers.d
    k = 20

    # vrf = Vrf(n, d, e)
    # alpha = " ".join(argv[1:])
    # pi = vrf.prove(alpha, k)
    # beta = vrf.proof2hash(pi)

    print("Public-key: {}".format(str(public_key)))
    print("Secret-key: {}".format(str(secret_key)))
    print("n: {}".format(str(n)))
    print("e: {}".format(str(e)))
    print("d: {}".format(str(d)))
    # print("K:" + k)

    # print(vrf_verifying(public_key, alpha, pi, k))

