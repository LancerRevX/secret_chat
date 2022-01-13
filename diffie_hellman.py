from sympy import isprime, randprime, is_primitive_root
from random import randint


class DiffieHellmanError(Exception):
    pass


def validate_values(p, g, A) -> bool:
    if not isprime(p):
        return False
    q = (p - 1) // 2
    if not isprime(q):
        return False
    if not 1 < g < (p - 1) or pow(g, q, p) == 1:
        return False
    if not 0 <= A < p:
        return False
    return True


def generate_g(q, p):
    for g in range(1, p-1):
        if pow(g, q, p) != 1:
            return g
    return None


def generate_q_and_p():
    q = randprime(2 ** 64, 2 ** 128)
    p = q * 2 + 1
    while True:
        if isprime(p):
            g = generate_g(q, p)
            if g is not None:
                break
        q = randprime(2 ** 64, 2 ** 128)
        p = q * 2 + 1
    return q, p


def generate_a(order):
    if order < 0:
        raise DiffieHellmanError
    a = randint(10**order, 10**(order+1)-1)
    return a


def calculate_A(p, g, a):
    if not isprime(p) or not 1 <= a or not is_primitive_root(g, p):
        raise DiffieHellmanError
    return pow(g, a, p)


def calculate_secret_key(p, a, B) -> int:
    if not isprime(p) or not 1 <= a or not 0 <= B < p:
        raise DiffieHellmanError
    key = pow(B, a, p)
    return key
