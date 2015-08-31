#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""
Public cryptography tools.
"""

import random

_p = int(
    """0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd12902"""
    """4e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a4"""
    """31b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42"""
    """e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe"""
    """649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8"""
    """fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d6"""
    """70c354e4abc9804f1746c08ca237327ffffffffffffffff""",
    base=16
)
_g = 2


def dh_keys(p: int=_p, g: int=_g) -> tuple:
    """
    Generate Diffie-Hellman keys.

    :param p: The group modulo.
    :param g: A primitive root of p.
    :return: p, g, the private and the public DH keys.
    """
    private_key = random.randint(0, p)
    public_key = pow(g, private_key, p)

    return p, g, private_key, public_key

