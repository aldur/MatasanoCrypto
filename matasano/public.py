#!/usr/bin/env/ python
# encoding: utf-8

"""
Public cryptography tools.
"""

import random
import collections
import functools

import matasano.hash
import matasano.blocks
import matasano.util
import matasano.mac
import matasano.math

__author__ = 'aldur'

dh_nist_p = int(
    """0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd12902"""
    """4e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a4"""
    """31b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42"""
    """e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe"""
    """649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8"""
    """fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d6"""
    """70c354e4abc9804f1746c08ca237327ffffffffffffffff""",
    base=16
)
dh_nist_g = 2

dsa_p = int(
    """800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171"""
    """e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3"""
    """226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8f"""
    """da812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d"""
    """015efc871a584471bb1""",
    base=16
)

dsa_q = int(
    """f4f47f05794b256174bba6e9b396a7707e563c5b""",
    base=16
)

dsa_g = int(
    """5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"""
    """458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"""
    """322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"""
    """0f5b64c36b625a097f1651fe775323556fe00b3608c887892"""
    """878480e99041be601a62166ca6894bdd41a7054ec89f756ba"""
    """9fc95302291""",
    base=16

)

"""
DH parameters.
"""
DH_params = collections.namedtuple(
    "DH_params", ["p", "g", "priv", "pub"]
)


def dh_keys(p: int = dh_nist_p, g: int = dh_nist_g) -> DH_params:
    """
    Generate Diffie-Hellman keys.

    :param p: The group modulo.
    :param g: A primitive root of p.
    :return: p, g, the private and the public DH keys.
    """
    private_key = random.randint(0, p)
    public_key = pow(g, private_key, p)

    return DH_params(p, g, private_key, public_key)


"""
Store RSA public key.
"""
RSA_Pub = collections.namedtuple(
    'RSA_Pub', ['e', 'n']
)

"""
Store RSA private key.
"""
RSA_Priv = collections.namedtuple(
    'RSA_Priv', ['d', 'n']
)

"""
The key pair.
"""
RSA_Keys = collections.namedtuple(
    'RSA_Keys', ['priv', 'pub']
)


def rsa_keys(p: int = None, q: int = None, e: int = 3) -> RSA_Keys:
    """
    Generate a new set of RSA keys.
    If p and q are not provided (<= 1),
    then they will be generated.

    :param p: A big prime.
    :param q: A big prime.
    :param e: The default public key.
    :return: The RSA private and public keys.
    :raise Exception: If provided p and q are invalid.
    """

    if not p or p <= 1:
        p = matasano.math.random_big_prime(e=e)
    if not q or q <= 1:
        q = matasano.math.random_big_prime(e=e)

    n = p * q
    phi_n = (p - 1) * (q - 1)
    d = matasano.math.modinv(e, phi_n)

    return RSA_Keys(RSA_Priv(d, n), RSA_Pub(e, n))


def rsa_encrypt(key: RSA_Pub, message: bytes) -> int:
    """
    Encrypt the message by using RSA.
    Note, this is a deterministic, textbook implementation.

    :param key: The RSA public key (e, n).
    :param message: The message to be encrypted.
    :return: The encryption.
    """
    e, n = key

    return pow(
        int.from_bytes(message, byteorder="little"),
        e,
        n
    )


def rsa_decrypt(key: RSA_Priv, cipher: int) -> bytes:
    """
    Decrypt the message by using RSA.

    :param key: The RSA private key (d, n).
    :param cipher: The message to be decrypted.
    :return: The decrypted message.
    """
    d, n = key

    return matasano.util.bytes_for_int(
        pow(
            cipher,
            d,
            n
        )
    )


def rsa_sign(key: RSA_Priv, message_digest_block: bytes) -> int:
    """
    Sign the message by using RSA.

    :param key: The RSA private key (d, n).
    :param message_digest_block: The padded digest of the message to be signed.
    :return: The signature of the message.
    """
    assert key
    assert message_digest_block

    d, n = key
    message_digest_block = int.from_bytes(
        message_digest_block, byteorder="little"
    )

    return pow(
        message_digest_block,
        d,
        n
    )


def rsa_verify(
        key: RSA_Pub,
        message_digest_block: bytes,
        signature: int
) -> bool:
    """
    Verify the message's signature by using RSA.

    :param key: The RSA private key (d, n).
    :param message_digest_block: The padded hash of the
        message whose signature needs to be signed.
    :param signature: The provided message signature.
    :return: True if the signature is correct.
    """
    assert key
    assert message_digest_block
    assert signature

    e, n = key.e, key.n

    signed_message = matasano.util.bytes_for_int(
        pow(signature, e, n)
    )
    return signed_message == message_digest_block


"""
Store DSA public key.
"""
DSA_Pub = collections.namedtuple(
    'DSA_Pub', ['y', 'p', 'q', 'g']
)

"""
Store DSA private key.
"""
DSA_Priv = collections.namedtuple(
    'DSA_Priv', ['x', 'p', 'q', 'g']
)

"""
The key pair.
"""
DSA_Keys = collections.namedtuple(
    'DSA_Keys', ['priv', 'pub']
)


def dsa_keys(
        g: int = dsa_g,
        p: int = dsa_p,
        q: int = dsa_q,
) -> DSA_Keys:
    """
    Generate a new pair of DSA user keys.

    :param g: DSA parameter g.
    :param p: DSA parameter p.
    :param q: DSA parameter q.
    """
    x = random.randint(1, q - 1)
    y = pow(g, x, p)

    return DSA_Keys(
        DSA_Priv(x, p, q, g),
        DSA_Pub(y, p, q, g),
    )


"""
DSA digital signature.
"""
DSA_Signature = collections.namedtuple(
    'DSA_Signature', ['r', 's']
)

DSA_hash_to_int = functools.partial(
    int.from_bytes,
    byteorder='big'
)


def dsa_sign(
        message: bytes,
        private: DSA_Priv,
        hash_f=matasano.hash.SHA256,
        hash_to_int=DSA_hash_to_int
) -> DSA_Signature:
    """
    The DSA signing algorithm.

    :param message: The message to be signed.
    :param private: The DSA private key.
    :param hash_f: The hash function used.
    :param hash_to_int: The function to convert a hash to an int.
    :return: A new digital signature for the message.
    """
    x, p, q, g = private

    r = 0
    s = 0

    digest = hash_to_int(hash_f(message))

    while s == 0:
        k = random.randint(1, q - 1)
        k_inv = matasano.math.modinv(k, q)

        r = pow(g, k, p) % q
        if r != 0:
            s = k_inv * (digest + x * r) % q

    return DSA_Signature(r, s)


def dsa_verify(
        message: bytes,
        signature: DSA_Signature,
        public: DSA_Pub,
        hash_f=matasano.hash.SHA256,
        hash_to_int=DSA_hash_to_int
) -> bool:
    """
    Verify the digital signature for the given message.

    :param message: The signed message.
    :param signature: The signature to be verified.
    :param public: The public key of the signer.
    :param hash_f: The hash function used.
    :param hash_to_int: The function to convert a hash to an int.
    :return: Whether the digital signature is valid.
    """
    r, s = signature
    y, p, q, g = public

    if not (0 < r < s or 0 < s < q):
        return False

    w = matasano.math.modinv(s, q)
    u_one = (hash_to_int(hash_f(message)) * w) % q
    u_two = (r * w) % q
    v = ((pow(g, u_one, p) * pow(y, u_two, p)) % p) % q

    return v == r


class DHEntity:
    """
    The entity initiating the DH key exchange protocol.
    """

    @staticmethod
    def session_key_to_16_aes_bytes(k: int) -> bytes:
        """
        Convert a DH session key to an AES-eligible 16 bytes key.
        Encode the key to little endian bytes,
        hash them and return the 16-bytes prefix.

        :param k: The session key.
        :return: An AES key derived from k.
        """
        assert k >= 0

        h = matasano.hash.SHA1
        digest = h(
            matasano.util.bytes_for_int(k)
        )

        assert len(digest) > 16
        return digest[:16]

    @staticmethod
    def decipher_received_message(k: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt the received message and return the contained plaintext.

        :param k: The key.
        :param ciphertext: The ciphertext.
        :return: The plaintext.
        """
        iv, ciphertext = ciphertext[-16:], ciphertext[:-16]
        plaintext, _ = matasano.blocks.aes_cbc(
            key=k,
            b=ciphertext,
            iv=iv,
            decrypt=True
        )
        return plaintext

    def __init__(self):
        self._keys = None
        self._session_key = -1  # Invalid, has to be >= 0

    def dh_protocol(self, receiver, p: int = None, g: int = None):
        """
        Generate a new pair of keys.
        Initiate a new DH-key exchange protocol.

        :param receiver: The responding entity of the DH-protocol.
        :param p: The group modulo.
        :param g: A primitive root of p.
        """
        assert receiver
        assert receiver != self

        if p and g:
            _, _, a, pub_a = self._keys = dh_keys(p, g)
        else:
            p, g, a, pub_a = self._keys = dh_keys()
        pub_b = receiver.dh_protocol_respond(p, g, pub_a)
        self._session_key = pow(pub_b, a, p)

    def dh_protocol_respond(self, p: int, g: int, pub_a: int) -> int:
        """
        Handle a DH protocol request.
        Generate a new pair keys,
        return the public one to the caller,
        and store the session key computed
        from the caller's public key.

        :param p: The group modulo.
        :param g: A primitive root of p.
        :param pub_a: The caller's DH public key.
        """
        _, _, b, pub_b = self._keys = dh_keys(p, g)
        self._session_key = pow(pub_a, b, p)
        return pub_b

    def send_and_receive(self, receiver, message: bytes) -> bytes:
        """
        Send an encrypted message as follows:
        - key = SHA1(session_key)[:16]
        - iv = random IV
        - message
        send: AES_CBC(message) || iv

        :param receiver: The receiver.
        :param message:  The message to be sent.
        :return: The received answer (if any).
        """
        key = DHEntity.session_key_to_16_aes_bytes(
            self._session_key
        )
        ciphertext, iv = matasano.blocks.aes_cbc(
            key=key,
            b=message,
            random_iv=True
        )
        ciphertext = receiver.receive_and_send_back(ciphertext + iv)
        plaintext = DHEntity.decipher_received_message(key, ciphertext)

        return plaintext

    def receive_and_send_back(self, ciphertext: bytes) -> bytes:
        """
        Receive an encrypted message,
        decrypt it, generate a new random IV,
        encrypt it again and send it back.

        :param ciphertext: The received ciphertext.
        :return: A new ciphertext, whose IV vector has been changed.
        """
        key = DHEntity.session_key_to_16_aes_bytes(
            self._session_key
        )
        plaintext = DHEntity.decipher_received_message(key, ciphertext)
        ciphertext, iv = matasano.blocks.aes_cbc(
            key,
            plaintext,
            random_iv=True
        )
        return ciphertext + iv


class DHAckEntity(DHEntity):
    """
    Before starting the DH protocol send the group parameters
    and wait for an ACK.
    """

    def __init__(self):
        super(DHAckEntity, self).__init__()
        self._p, self._g = dh_nist_p, dh_nist_g

    def set_group_parameters(self, p: int, g: int):
        """
        Setup the group parameters and return.

        :param p: The group modulo.
        :param g: A primitive root of p.
        :return: True.
        """
        if p and g:
            self._p, self._g = p, g
        return True

    def dh_protocol(self, receiver, p: int = None, g: int = None):
        """
        Send the group parameters to the receiver and wait for an ACK.
        Generate a new pair of keys.
        Initiate a new DH-key exchange protocol.

        :param p: The group modulo.
        :param g: A primitive root of p.
        :param receiver: The responding entity of the DH-protocol.
        """
        receiver.set_group_parameters(p, g)
        super(DHAckEntity, self).dh_protocol(receiver, p, g)

    def dh_protocol_respond(self, p: int, g: int, pub_a: int) -> int:
        """
        Handle a DH protocol request.
        Generate a new pair keys,
        return the public one to the caller,
        and store the session key computed
        from the caller's public key.

        :param p: The group modulo.
        :param g: A primitive root of p.
        :param pub_a: The caller's DH public key.
        """
        assert self._p == p
        assert self._g == g
        return super(DHAckEntity, self).dh_protocol_respond(self._p, self._g, pub_a)


class SRPServer:
    """
    The server entity in the SRP protocol.

    :param password: The negotiated password.
    :param n: A NIST prime.
    :param g: A primitive root of n.
    :param k: An int.
    """

    def __init__(
            self,
            password: bytes,
            n: int = dh_nist_p,
            g: int = 2,
            k: int = 3
    ):
        self.N = n
        self.g = g
        self.k = k

        self._password = password
        self._K = -1
        self._salt = -1

    def _srp_generate(self) -> tuple:
        """
        Generate a new SRP.

        :return: the generated int and the salt (as bytes).
        """
        salt = matasano.util.bytes_for_int(
            random.randint(0, self.N)
        )
        digest = matasano.hash.SHA256(salt + self._password)
        x = int.from_bytes(digest, 'little')
        v = pow(self.g, x, self.N)

        return v, salt

    def srp_protocol_one(self, A: int) -> tuple:
        """
        Complete the phase one of the protocol, responding to the client.

        :param A: The client's public key.
        """
        v, self._salt = self._srp_generate()
        b = random.randint(0, self.N)
        B = self.k * v + pow(self.g, b, self.N)

        u = int.from_bytes(
            matasano.hash.SHA256(
                matasano.util.bytes_for_int(A) +
                matasano.util.bytes_for_int(B)
            ),
            byteorder='little'
        )

        s = pow(
            A * pow(v, u, self.N),
            b,
            self.N
        )

        self._K = matasano.hash.SHA256(
            matasano.util.bytes_for_int(s)
        )
        return self._salt, B

    def srp_protocol_two(self, signature: bytes) -> bool:
        """
        Check the signature against HMAC-SHA256(k, salt).

        :param signature: The client's produced MAC.
        :return: Whether the signature is correct.
        """
        truth = matasano.mac.hmac_sha256(
            self._K,
            self._salt
        )

        return signature == truth


class SRPClient:
    """
    The client initiating the SRP protocol.

    :param password: The password.
    :param server: The server.
    :param n: A NIST prime.
    :param g: A primitive root of n.
    :param k: A positive integer.
    """

    def __init__(
            self,
            password: bytes,
            server: SRPServer,
            n: int = dh_nist_p,
            g: int = 2,
            k: int = 3,
    ):
        self.server = server
        self.N = n
        self.g = g
        self.k = k

        self._password = password
        self.key = -1

    def srp_protocol(self) -> bool:
        """
        The SRP protocol,
        as started from the client.
        """
        a = random.randint(0, self.N)
        A = pow(self.g, a, self.N)

        salt, B = self.server.srp_protocol_one(
            A
        )

        u = int.from_bytes(
            matasano.hash.SHA256(
                matasano.util.bytes_for_int(A) +
                matasano.util.bytes_for_int(B)
            ),
            byteorder='little'
        )

        x = int.from_bytes(
            matasano.hash.SHA256(
                salt + self._password
            ), byteorder="little"
        )

        s = pow(
            B - self.k * pow(self.g, x, self.N),
            a + u * x,
            self.N
        )

        self.key = matasano.hash.SHA256(
            matasano.util.bytes_for_int(s)
        )

        return self.server.srp_protocol_two(
            matasano.mac.hmac_sha256(
                self.key,
                salt
            )
        )


class SRPClientFakeA(SRPClient):
    """
    The client initiating the SRP protocol.

    :param server: The server.
    :param n: A NIST prime.
    :param g: A primitive root of n.
    :param k: A positive integer.
    :param A: A custom public key for the client s.t. A % N == 0.
    """

    def __init__(
            self,
            server: SRPServer,
            n: int = dh_nist_p,
            g: int = 2,
            k: int = 3,
            A: int = -1
    ):
        super().__init__(bytes(), server, n, g, k)

        if A != -1:
            assert A % n == 0
        self.A = A

    def srp_protocol(self) -> bool:
        """
        The SRP protocol,
        as started from the client.
        """
        if self.A == -1:
            return super().srp_protocol()
        else:
            A = self.A

            salt, _ = self.server.srp_protocol_one(
                A
            )

            # Server's session key will always be 0
            self.key = matasano.hash.SHA256(
                matasano.util.bytes_for_int(0)
            )

            return self.server.srp_protocol_two(
                matasano.mac.hmac_sha256(
                    self.key,
                    salt
                )
            )


class SimplifiedSRPServer(SRPServer):
    """
    The server entity in the simplified SRP protocol.
    """

    def srp_protocol_one(self, A: int) -> tuple:
        """
        Complete the phase one of the protocol, responding to the client.

        :param A: The client's public key.
        """
        v, self._salt = self._srp_generate()
        b = random.randint(0, self.N)
        B = pow(self.g, b, self.N)

        u = random.randint(0, (2 ** 128) - 1)  # 128 bit random number

        s = pow(
            A * pow(v, u, self.N),
            b,
            self.N
        )

        self._K = matasano.hash.SHA256(
            matasano.util.bytes_for_int(s)
        )

        return self._salt, B, u


class SimplifiedSRPClient(SRPClient):
    """
    The client initiating the simplified SRP protocol.

    :param password: The password.
    :param server: The server.
    :param n: A NIST prime.
    :param g: A primitive root of n.
    :param k: A positive integer.
    """

    def __init__(
            self,
            password: bytes,
            server: SimplifiedSRPServer,
            n: int = dh_nist_p,
            g: int = 2,
            k: int = 3,
    ):
        super().__init__(password, server, n, g, k)

    def srp_protocol(self) -> bool:
        """
        The simplified SRP protocol,
        as started from the client.
        """
        a = random.randint(0, self.N)
        A = pow(self.g, a, self.N)

        salt, B, u = self.server.srp_protocol_one(A)

        x = int.from_bytes(
            matasano.hash.SHA256(
                salt + self._password
            ), byteorder="little"
        )

        s = pow(
            B,
            a + u * x,
            self.N
        )

        self.key = matasano.hash.SHA256(
            matasano.util.bytes_for_int(s)
        )

        return self.server.srp_protocol_two(
            matasano.mac.hmac_sha256(
                self.key,
                salt
            )
        )
