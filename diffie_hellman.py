from sympy import isprime, randprime
from random import randint


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


def generate_values() -> tuple[int, int, int, int]:
    q = randprime(2**64, 2**128)
    p = q * 2 + 1
    while True:
        if isprime(p):
            g = generate_g(q, p)
            if g is not None:
                break
        q = randprime(2**64, 2**128)
        p = q * 2 + 1

    a = randint(1, p)
    A = pow(g, a, p)
    return p, g, A, a


def calculate_secret_key(p, g, A) -> tuple[int, int]:
    b = randint(1, p)
    B = pow(g, b, p)
    key = pow(A, b, p)
    return B, key
