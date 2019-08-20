# from https://github.com/ericchenmelt/VDF/blob/master/sloth_vdf.py

import datetime
import time

p = 73237431696005972674723595250817150843
vdf_prime = p

def sqrt_mod_p_verify(y, x, p):
    if pow(y, 2) % p == x % p:
        return True
    else:
        return False


def quad_res(x, p):
    return pow(x, (p - 1) // 2, p) == 1


def mod_sqrt_op(x, p):
    if quad_res(x, p):
        return x
    else:
        y = pow(x, (p + 1) // 4, p)
    return y


def mod_op(x, t):  # hash operation on an int with t iternations
    x = x % p
    start = datetime.datetime.now()
    for i in range(t):
        x = mod_sqrt_op(x, p)
    end = datetime.datetime.now()
    print(end - start)
    return x


def mod_verif(y, x, t):
    start = datetime.datetime.now()
    for i in range(t):
        y = pow(int(y), 2, p)
    if not quad_res(y, p):
        y = (-y) % p
    end = datetime.datetime.now()
    if x % p == y or (-x) % p == y:
        return True
    else:
        return False

def vdf_execute(x,t):
    return mod_op(x,t)

def vdf_verify(y,x,t):
    return mod_verif(y,x,t)

if __name__ == '__main__':

    print ('started')
    x = 35419308290030269702074013462993892045 #612 #8080
    x = x % p
    t = 99999
    start = time.time()
    y = mod_op(x, t)
    end = time.time()
    print('Elapsed: ',format(end - start,'.3f'))
    start = time.time()
    print(mod_verif(y, x, t), '****')
    end=time.time()
    print ('Verify Elapsed: ',format(end - start,'.3f'))