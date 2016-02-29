#!/usr/bin/env python
# encoding: utf-8

"""The main file."""

import matasano.util
import matasano.stats
import matasano.blocks
import matasano.oracle
import matasano.attacker
import matasano.prng
import matasano.mac
import matasano.math
import matasano.public
import matasano.hash

import base64
import binascii
import argparse
import io
import sys
import contextlib
import functools
import colorama
import pkg_resources
import typing

__author__ = "aldur"


def challenge(challenge_f):
    """
    Decorator for challenges function.

    :param challenge_f: The challenge function.
    :return: The decorated function.
    """

    class Tee(io.StringIO):
        """
        Print standard output as usual,
        and at the same time keep track of what
        is being printed.
        """

        def write(self, b: bytes):
            """
            Write the buffer on the standard output
            before calling the super implementation.

            :param b: The buffer to be written.
            """
            sys.__stdout__.write(b)
            return super().write(b)

    @functools.wraps(challenge_f)
    def decorated_challenge():
        """
        Execute the function and return to screen the result.
        """
        captured_stdout = Tee()
        print("Executing challenge: {}.\n".format(challenge_f.__name__))

        with contextlib.redirect_stdout(captured_stdout):
            result = challenge_f()

        v = captured_stdout.getvalue()
        if v and not v.endswith("\n\n"):
            print("")

        if result is not None:
            print(
                "{}Challenge {}.{}".format(
                    colorama.Fore.GREEN if result else colorama.Fore.RED,
                    "completed" if result else "failed",
                    colorama.Fore.RESET
                ))
        else:
            print("Challenge did not require explicit completion, you're good to go.")

        return result

    return decorated_challenge


@challenge
def one():
    """http://cryptopals.com/sets/1/challenges/1/"""
    hex_input = "49276d206b696c6c696e6720796f7" \
                "57220627261696e206c696b652061" \
                "20706f69736f6e6f7573206d75736" \
                "8726f6f6d"
    expected_b64_output = b"SSdtIGtpbGxpbmcgeW" \
                          b"91ciBicmFpbiBsaWtl" \
                          b"IGEgcG9pc29ub3VzIG" \
                          b"11c2hyb29t"
    print("HEX: {}".format(hex_input))
    hex_input = bytearray.fromhex(hex_input)
    b64_output = matasano.util.hex_to_b64(hex_input)
    print("B64: {}".format(b64_output.decode("ascii")))

    return b64_output == expected_b64_output


@challenge
def two():
    """http://cryptopals.com/sets/1/challenges/2/"""
    a = bytearray.fromhex("1c0111001f010100061a024b53535009181c")
    b = bytearray.fromhex("686974207468652062756c6c277320657965")

    c = bytearray(matasano.util.xor(a, b))
    print("'{}' xor '{}' = '{}'".format(
        a.decode("ascii"), b.decode("ascii"), c.decode("ascii")
    ))

    return c == bytes.fromhex("746865206b696420646f6e277420706c6179")


@challenge
def three():
    """http://cryptopals.com/sets/1/challenges/3/"""
    s = bytearray.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )
    key = matasano.stats.most_likely_xor_chars(s)[0]
    plaintext = matasano.util.xor_char(s, key).decode("ascii")
    print("Key: {}, Plaintext: {}.".format(key, plaintext))


@challenge
def four():
    """http://cryptopals.com/sets/1/challenges/4/"""
    input_path = pkg_resources.resource_filename(__name__, "input/4.txt")

    with open(input_path) as f:
        plaintexts = []
        for line in f:
            b = bytes.fromhex(line.rstrip())
            try:
                c = matasano.stats.most_likely_xor_chars(b)[0]
                plaintext = matasano.util.xor_char(b, c).decode("ascii")
                plaintexts.append(plaintext)
            except UnicodeDecodeError:
                pass

        print("Plaintext found: {}".format(
            min(
                plaintexts,
                key=lambda p: matasano.stats.chi_squared(p)
            )
        ))


@challenge
def five():
    """http://cryptopals.com/sets/1/challenges/5/"""
    lines = b"Burning 'em, if you ain't quick and nimble\n" \
            b"I go crazy when I hear a cymbal"
    key = "ICE".encode("ascii")
    expected = b"0b3637272a2b2e63622c2e69692a23693a2a3c63" \
               b"24202d623d63343c2a26226324272765272a282b" \
               b"2f20430a652e2c652a3124333a653e2b2027630c" \
               b"692b20283165286326302e27282f"

    result = binascii.hexlify(matasano.util.repeating_xor(lines, key))
    print("Result: {}".format(
        result.decode("ascii")
    ))
    return result == expected


@challenge
def six():
    """http://cryptopals.com/sets/1/challenges/6/"""
    input_path = pkg_resources.resource_filename(__name__, "input/6.txt")
    with open(input_path, 'r') as f:
        s = ''.join(l.rstrip() for l in f.readlines())
        b = base64.b64decode(s)

        k_len = matasano.stats.most_likely_key_length(b)
        blocks = matasano.blocks.split_blocks(b, k_len)

        key = tuple(
            map(
                lambda x: matasano.stats.most_likely_xor_chars(x)[0],
                blocks
            )
        )

        print(
            "Key found: \"{}\"".format(''.join(key)),
        )
        print(
            "Plaintext:\n{}".format(
                matasano.util.repeating_xor(
                    b, bytes(ord(c) for c in key)
                ).decode("ascii")
            ),
        )


@challenge
def seven():
    """http://cryptopals.com/sets/1/challenges/7/"""
    input_path = pkg_resources.resource_filename(__name__, "input/7.txt")
    with open(input_path, 'r') as f:
        key = b"YELLOW SUBMARINE"
        s = base64.b64decode(f.read())
        print("Decrypted:\n{}".format(
            matasano.blocks.aes_ecb(key, s, decrypt=True).decode("ascii")
        ))


@challenge
def eight():
    """http://cryptopals.com/sets/1/challenges/8/"""
    input_path = pkg_resources.resource_filename(__name__, "input/8.txt")
    with open(input_path, 'rb') as f:
        for line in f:
            if matasano.blocks.any_equal_block(line):
                print("Likely to be ECB.")


@challenge
def nine():
    """http://cryptopals.com/sets/2/challenges/9/"""
    b = "YELLOW SUBMARINE".encode("ascii")
    size = 20
    padding = matasano.blocks.pkcs_7(b, size)
    print("PKCS padding: {}".format(padding))
    return padding == b'YELLOW SUBMARINE\x04\x04\x04\x04'


@challenge
def ten():
    """http://cryptopals.com/sets/2/challenges/10/"""
    input_path = pkg_resources.resource_filename(__name__, "input/10.txt")
    with open(input_path, 'r') as f:
        b = base64.b64decode(f.read())
        key = "YELLOW SUBMARINE".encode("ascii")
        print(
            "Decrypted:\n{}".format(
                matasano.blocks.aes_cbc(key, b, decrypt=True)[0].decode("ascii")
            )
        )


@challenge
def eleven():
    """http://cryptopals.com/sets/2/challenges/11/"""
    oracle = matasano.oracle.OracleAesEcbCbc()

    """
    Pass to the oracle something that,
    even after the random adding,
    is smaller than 4 blocks and is all 0s.
    In this way we'll have the two middle blocks
    always full of 0s. ECB is stateless, so they
    will be equal.
    If they're not, then it's CBC.
    """
    b = b"\x00" * ((16 * 4) - 10)
    o = oracle.challenge(b)

    ecb = matasano.blocks.any_equal_block(o)
    print(
        "Guess - Oracle used: {}.".format(
            "ECB" if ecb else "CBC"
        )
    )
    result = oracle.guess(ecb)
    print(
        "Guess is {}.".format(
            "correct" if result else "wrong"
        )
    )
    return result


@challenge
def twelve():
    """http://cryptopals.com/sets/2/challenges/12/"""
    oracle = matasano.oracle.OracleByteAtATimeEcb()
    attacker = matasano.attacker.AttackerByteAtATimeEcb(oracle)
    result = attacker.attack()
    print("Guessed hidden string is:\n{}".format(
        attacker.unhidden_string.decode("ascii")
    ))
    return result


@challenge
def thirteen():
    """http://cryptopals.com/sets/2/challenges/13/"""
    oracle = matasano.oracle.OracleProfileForUser()
    attacker = matasano.attacker.AttackerProfileForUser(oracle)
    attacker.get_base_user_profile()
    attacker.get_role_block()
    result = attacker.attack()
    return result


@challenge
def fourteen():
    """http://cryptopals.com/sets/2/challenges/14/"""
    oracle = matasano.oracle.OracleHarderByteAtATimeEcb()
    attacker = matasano.attacker.AttackerHarderByteAtATimeEcb(oracle)
    attacker.discover_block_size()

    print("Prefix len: {}.".format(
        attacker.discover_fixed_string_len())
    )

    result = attacker.attack()
    print("Guessed hidden string is:\n{}".format(
        attacker.unhidden_string.decode("ascii")
    ))
    return result


@challenge
def fifteen():
    """http://cryptopals.com/sets/2/challenges/15/"""
    pads = (
        b"ICE ICE BABY\x04\x04\x04\x04",
        b"ICE ICE BABY\x05\x05\x05\x05",
        b"ICE ICE BABY\x01\x02\x03\x04"
    )

    for padded in pads:
        try:
            matasano.blocks.un_pkcs_7(padded, 16)
            print("Padded buffer {} is valid.".format(padded))
        except matasano.blocks.BadPaddingException:
            print("Padded buffer {} is invalid.".format(padded))


@challenge
def sixteen():
    """http://cryptopals.com/sets/2/challenges/16/"""
    oracle = matasano.oracle.OracleBitflipping(
        matasano.blocks.aes_cbc, needs_padding=True
    )
    attacker = matasano.attacker.AttackerBitFlippingCBC(oracle)

    result = attacker.attack()
    return result


@challenge
def seventeen():
    """http://cryptopals.com/sets/3/challenges/17/"""
    input_path = pkg_resources.resource_filename(__name__, "input/17.txt")
    oracle = matasano.oracle.OracleCBCPadding(input_path)
    attacker = matasano.attacker.AttackerCBCPadding(oracle)

    result = attacker.attack()
    print("Guessed hidden string is:\n{}".format(
        attacker.discovered_string.decode("ascii")
    ))
    print("Decoding it produces:\n{}".format(
        base64.b64decode(attacker.discovered_string).decode("ascii")
    ))
    return result


@challenge
def eighteen():
    """http://cryptopals.com/sets/3/challenges/18/"""
    key = "YELLOW SUBMARINE".encode("ascii")
    b = base64.b64decode(
        """
        L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/
        2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
        """
    )
    print("The decryption produced: \n{}.".format(
        matasano.blocks.aes_ctr(
            key, b
        )[0].decode("ascii")
    ))


def _fixed_nonce_ctr(oracle: matasano.oracle.OracleFixedNonceCTR):
    attacker = matasano.attacker.AttackerFixedNonceCTR(oracle)

    result = attacker.attack()
    print("Discovered strings:\n{}".format(
        "\n".join(b.decode("ascii") for b in attacker.discovered_strings)
    ))
    return result


@challenge
def nineteen():
    """http://cryptopals.com/sets/3/challenges/19/"""
    input_path = pkg_resources.resource_filename(__name__, "input/19.txt")
    oracle = matasano.oracle.OracleFixedNonceCTR(input_path)
    return _fixed_nonce_ctr(oracle)


@challenge
def twenty():
    """http://cryptopals.com/sets/3/challenges/20/"""
    input_path = pkg_resources.resource_filename(__name__, "input/20.txt")
    oracle = matasano.oracle.OracleFixedNonceCTR(input_path)
    return _fixed_nonce_ctr(oracle)


@challenge
def twentyone():
    """http://cryptopals.com/sets/3/challenges/21/"""
    mt_prng = matasano.prng.MT19937(42)
    print("Randomly generated numbers: {}".format(
        [mt_prng.extract_number() for _ in range(10)]
    ))


@challenge
def twentytwo():
    """http://cryptopals.com/sets/3/challenges/22/"""
    print("Please wait while the oracle does its job...")
    oracle = matasano.oracle.OracleMT19937Seed()
    attacker = matasano.attacker.AttackerMT19937Seed(oracle)
    result = attacker.attack()
    print("Discovered seed:\n{}".format(
        attacker.discovered_seed
    ))
    return result


@challenge
def twentythree():
    """http://cryptopals.com/sets/3/challenges/23/"""
    oracle = matasano.oracle.OracleMT19937Clone()
    attacker = matasano.attacker.AttackerMT19937Clone(oracle)
    result = attacker.attack()
    print("Discovered next random numbers:\n{}".format(
        attacker.next_random_numbers
    ))
    return result


@challenge
def twentyfour():
    """http://cryptopals.com/sets/3/challenges/24/"""
    oracle = matasano.oracle.OracleMT19937Stream()
    attacker = matasano.attacker.AttackerMT19937Stream(oracle)
    print("Please wait while brute-forcing the oracle's seed...")
    result = attacker.attack()
    print("Discovered seed:\n{}".format(
        attacker.key
    ))
    return result


@challenge
def twentyfive():
    """http://cryptopals.com/sets/4/challenges/25/"""
    input_path = pkg_resources.resource_filename(__name__, "input/19.txt")
    with open(input_path, "rb") as inputFile:
        oracle = matasano.oracle.OracleRandomAccessCTR(
            inputFile.read()
        )
        attacker = matasano.attacker.AttackerRandomAccessCTR(oracle)
        print("Please wait while brute-forcing the oracle's plaintext...")
        result = attacker.attack()
        print("Discovered plaintext:\n{}".format(
            attacker.discovered_plaintext.decode("ascii")
        ))
        return result


@challenge
def twentysix():
    """http://cryptopals.com/sets/4/challenges/26/"""
    oracle = matasano.oracle.OracleBitflipping(
        matasano.blocks.aes_ctr
    )
    attacker = matasano.attacker.AttackerBitFlippingCTR(oracle)

    result = attacker.attack()
    return result


@challenge
def twentyseven():
    """http://cryptopals.com/sets/4/challenges/27/"""
    oracle = matasano.oracle.OracleCBCKeyIV()
    attacker = matasano.attacker.AttackerCBCKeyIV(oracle)

    result = attacker.attack()
    return result


@challenge
def twentyeight():
    """http://cryptopals.com/sets/4/challenges/28/"""
    key = b"SECRET"
    message = b"MESSAGE"

    print(
        "SHA1({} | {}) = {}".format(
            key.decode("ascii"),
            message.decode("ascii"),
            binascii.hexlify(
                matasano.mac.sha1_secret_prefix(key, message)
            ).decode("ascii")
        )
    )
    oracle = matasano.oracle.OracleCBCKeyIV()
    attacker = matasano.attacker.AttackerCBCKeyIV(oracle)

    result = attacker.attack()
    return result


@challenge
def twentynine():
    """http://cryptopals.com/sets/4/challenges/29/"""
    oracle = matasano.oracle.OracleSHA1KeyedMac()
    attacker = matasano.attacker.AttackerSHA1KeyedMac(oracle)

    result = attacker.attack()
    print(
        "Forged message: {}.\n"
        "Forged MAC: {}.".format(
            attacker.forged_message,
            binascii.hexlify(attacker.forged_mac).decode("ascii")
        )
    )
    return result


@challenge
def thirty():
    """http://cryptopals.com/sets/4/challenges/30/"""
    oracle = matasano.oracle.OracleMD4KeyedMac()
    attacker = matasano.attacker.AttackerMD4KeyedMac(oracle)

    result = attacker.attack()
    print(
        "Forged message: {}.\n"
        "Forged MAC: {}.".format(
            attacker.forged_message,
            binascii.hexlify(attacker.forged_mac).decode("ascii")
        )
    )
    return result


def _remote_sha1_hmac():
    oracle = matasano.oracle.OracleRemoteSHA1HMac()
    attacker = matasano.attacker.AttackerRemoteSHA1HMac(oracle)

    print("Please wait while brute-forcing the MAC...")
    result = attacker.attack()
    print(
        "Forged MAC: {}.".format(
            binascii.hexlify(attacker.forged_mac).decode("ascii")
        )
    )
    return result


@challenge
def thirtyone():
    """http://cryptopals.com/sets/4/challenges/31/"""
    return _remote_sha1_hmac()


@challenge
def thirtytwo():
    """http://cryptopals.com/sets/4/challenges/32/"""
    return _remote_sha1_hmac()


@challenge
def thirtythree():
    """http://cryptopals.com/sets/5/challenges/33/"""
    dh_params = matasano.public.dh_keys()
    print("Generated DH keys:\n{},\n{}.".format(
        dh_params.priv, dh_params.pub
    ))


@challenge
def thirtyfour():
    """http://cryptopals.com/sets/5/challenges/34/"""
    alice, bob = matasano.public.DHEntity(), matasano.public.DHEntity()
    eve = matasano.attacker.EavesdropperDH(alice, bob)

    result = eve.attack()
    print("Eavesdropped message: \"{}\".".format(
        eve.eavesdropped_message.decode("ascii")
    ))
    return result


@challenge
def thirtyfive():
    """http://cryptopals.com/sets/5/challenges/35/"""
    alice, bob = matasano.public.DHAckEntity(), matasano.public.DHAckEntity()

    results = []
    p = matasano.public.dh_nist_p
    for g in [1, p - 1, p]:
        print(
            "MITM for g equal to {}.".format(g)
        )
        eve = matasano.attacker.EavesdropperAckDH(alice, bob, g)

        result = eve.attack()
        print("Eavesdropped message: \"{}\".".format(
            eve.eavesdropped_message.decode("ascii")
        ))
        print("The attack result was: {}.".format(
            "success" if result else "failure"
        ))
        results.append(result)

    return all(results)


@challenge
def thirtysix():
    """http://cryptopals.com/sets/5/challenges/36/"""
    password = b"A secret password"
    server = matasano.public.SRPServer(password)
    client = matasano.public.SRPClient(password, server)

    result = client.srp_protocol()
    if result:
        print("Negotiated key: {}.".format(
            binascii.hexlify(client.key).decode("ascii")
        ))
    else:
        print("Something went wrong during the protocol.")

    return result


@challenge
def thirtyseven():
    """http://cryptopals.com/sets/5/challenges/37/"""
    password = b"A secret password"
    server = matasano.public.SRPServer(password)
    print(
        "Initiating SRP protocol client public key set to N."
    )
    # Client doesn't know the password.
    client = matasano.public.SRPClientFakeA(
        server,
        A=matasano.public.dh_nist_p
    )

    result = client.srp_protocol()
    if result:
        print("Negotiated key: {}.".format(
            binascii.hexlify(client.key).decode("ascii")
        ))
    else:
        print("Something went wrong during the protocol.")

    return result


@challenge
def thirtyeight():
    """http://cryptopals.com/sets/5/challenges/38/"""
    password = matasano.util.get_random_password()
    attacker = matasano.attacker.EavesdropperSimplifiedSRPServer()
    client = matasano.public.SimplifiedSRPClient(
        password,
        attacker
    )

    client.srp_protocol()
    result = attacker.attack()
    if result:
        print("Cracked password: {}.".format(
            attacker.client_password.decode("ascii")
        ))
    else:
        print("Something went wrong during the brute-force.")

    return result


@challenge
def thirtynine():
    """http://cryptopals.com/sets/5/challenges/39/"""
    private, public = matasano.public.rsa_keys()
    print(
        "Generated RSA keys.\ne: {}.\nd: {}.\nn: {}.".format(
            public.e, private.d, private.n
        )
    )


@challenge
def forty():
    """http://cryptopals.com/sets/5/challenges/40/"""
    message = b"Secret"

    ciphers_and_keys = list()
    for _ in range(3):
        _, public = matasano.public.rsa_keys(e=3)
        cipher = matasano.public.rsa_encrypt(
            public, message
        )
        ciphers_and_keys += [cipher, public]

    attacker = matasano.attacker.AttackerRSABroadcast(
        *ciphers_and_keys
    )

    result = attacker.attack() == message
    return result


@challenge
def fortyone():
    """http://cryptopals.com/sets/6/challenges/41/"""
    oracle = matasano.oracle.OracleUnpaddedRSARecovery()
    attacker = matasano.attacker.AttackerUnpaddedRSARecovery(oracle)

    result = attacker.attack()
    return result


@challenge
def fortytwo():
    """http://cryptopals.com/sets/6/challenges/42/"""
    oracle = matasano.oracle.OracleRSAPaddedSignatureVerifier(b"hi mom")
    attacker = matasano.attacker.AttackerRSAPaddedSignatureVerifier(oracle)

    result = attacker.attack()
    return result


@challenge
def fortythree():
    """http://cryptopals.com/sets/6/challenges/43/"""
    oracle = matasano.oracle.OracleDSAKeyFromNonce(
        matasano.oracle.OracleDSAKeyFromNonce.public_key
    )
    attacker = matasano.attacker.AttackerDSAKeyFromNonce(oracle)

    result = attacker.attack()
    print("Discovered private key: {}.".format(attacker.private_key_x))
    return result


@challenge
def fortyfour():
    """http://cryptopals.com/sets/6/challenges/44/"""
    oracle = matasano.oracle.OracleDSAKeyFromRepeatedNonce(
        matasano.oracle.OracleDSAKeyFromRepeatedNonce.public_key,
        pkg_resources.resource_filename(__name__, "input/44.txt")
    )
    attacker = matasano.attacker.AttackerDSAKeyFromRepeatedNonce(oracle)

    result = attacker.attack()
    print("Discovered private key: {}.".format(attacker.private_key_x))
    return result


@challenge
def fortyfive():
    """http://cryptopals.com/sets/6/challenges/45/"""
    private, public = matasano.public.dsa_keys(
        g=matasano.public.dsa_p + 1
    )

    results = []
    for b in [b"Hello, world", b"Goodbye, world"]:
        z = matasano.public.DSA_hash_to_int(
            matasano.hash.SHA256(b)
        )

        r = pow(public.y, z, public.p) % public.q
        s = (r * matasano.math.modinv(z, public.q)) % public.q
        signature = matasano.public.DSA_Signature(r, s)
        results.append(matasano.public.dsa_verify(
            b,
            signature,
            public
        ))

    return all(results)


@challenge
def fortysix():
    """http://cryptopals.com/sets/6/challenges/46/"""
    oracle = matasano.oracle.OracleRSAParity(
        base64.b64decode(
            b"VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5I"
            b"GFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ"
            b"=="
        )
    )
    attacker = matasano.attacker.AttackerRSAParity(oracle)

    result = attacker.attack()
    print("Discovered message: {}.".format(attacker.message.decode("ascii")))
    return result


def _b98():
    oracle = matasano.oracle.OracleRSAPadding(
        b"kick it, CC"
    )
    attacker = matasano.attacker.AttackerRSAPadding(oracle)

    print("Please wait while performing the attack...")
    print("Warning: this attack could take a long time.")
    result = attacker.attack()
    print("Discovered message: {}.".format(attacker.message.decode("ascii")))
    return result


@challenge
def fortyseven():
    """http://cryptopals.com/sets/6/challenges/47/"""
    return _b98()


@challenge
def fortyeight():
    """http://cryptopals.com/sets/6/challenges/48/"""
    return _b98()


@challenge
def fortynine():
    """http://cryptopals.com/sets/7/challenges/49/"""
    oracle = matasano.oracle.OracleCBCMac()
    attacker = matasano.attacker.AttackerCBCMacForge(oracle)

    result = attacker.attack()
    print("Found message: {}.\nForged MAC: {}.".format(
        attacker.message, binascii.hexlify(attacker.forged_mac).decode('ascii')
    ))
    return result


@challenge
def fifty():
    """http://cryptopals.com/sets/7/challenges/50/"""
    oracle = matasano.oracle.OracleCBCMacHash()
    attacker = matasano.attacker.AttackerCBCMacHash(oracle)

    result = attacker.attack()
    print("Original message: {}.\nCollision: {}.\nDigest: {}.".format(
        attacker.message, attacker.collision, binascii.hexlify(attacker.digest).decode('ascii')
    ))
    return result


@challenge
def fiftyone():
    """http://cryptopals.com/sets/7/challenges/51/"""
    oracle = matasano.oracle.OracleCompress(b"TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=")
    attacker = matasano.attacker.AttackerCompress(oracle)

    result = attacker.attack()
    print("Discovered session ID: {}.".format(attacker.session_id.decode('ascii')))
    return result


@challenge
def fiftytwo():
    """http://cryptopals.com/sets/7/challenges/52/"""
    weak_hash = matasano.hash.weak_iterated_hash
    semi_weak_hash_output = 3  # bytes
    semi_weak_hash = matasano.hash.make_md_hash_block(
        output_len=semi_weak_hash_output,
        block_len=16,
        block_cipher=matasano.blocks.aes_ecb,
        padding_function=matasano.blocks.naive_block_padding
    )

    def f(hash_f, n: int):
        """
        Given the hash function, find 2 ** n colliding messages.

        :param hash_f: The hash function to be used.
        :param n: A integer.
        :return: The 2 ** n colliding messages.
        """
        collisions = []

        # Find the collisions.
        previous_collision = b''
        for k in range(n):
            hashes = {}

            for i in range(0, 2 ** 16):
                h = hash_f(matasano.util.bytes_for_int(i, length=16), state=previous_collision)

                if h in hashes:
                    previous_collision = h
                    collisions.append((hashes[h], i))
                    break
                else:
                    hashes[h] = i
            else:
                assert False, "Something went wrong while finding collisions"

        # And build the colliding messages.
        messages = {matasano.util.bytes_for_int(n, length=16) for n in collisions[0]}
        for suffixes in collisions[1:]:
            messages = {
                message + matasano.util.bytes_for_int(suffix, length=16)
                for message in messages
                for suffix in suffixes
            }

        return messages

    semi_weak_hash_output *= 4  # Halved, to bits
    weak_collisions = f(weak_hash, semi_weak_hash_output)
    assert len(weak_collisions) == 2 ** semi_weak_hash_output

    semi_weak_collisions = set()
    for c in weak_collisions:
        h = semi_weak_hash(c)
        if h in semi_weak_collisions:
            print("Collision found: {}.".format(c))
            return True
        else:
            semi_weak_collisions.add(h)

    return False


@challenge
def fiftythree():
    """http://cryptopals.com/sets/7/challenges/53/"""
    # Yes, this is not a 'proper' MD length-padded hash,
    # but we make sure to respect the rules below.
    weak_hash = matasano.hash.weak_iterated_hash
    block_size = 16

    def alpha_collision(alpha: int, initial_state: bytes) -> typing.Tuple[bytes, bytes, bytes]:
        """
        As described, generate a collisions between a single block message
        and a message of length `alpha`.

        :param alpha: The fixed length parameter.
        :param initial_state: The initial state of the hash function.
        :return: The collision and the two colliding messages.
        """
        single_block_hashes = {
            weak_hash(m, state=initial_state): m
            for m in (matasano.util.bytes_for_int(m, block_size) for m in range(2 ** block_size))
        }

        dummy = b"\x42" * block_size * alpha
        dummy_state = weak_hash(dummy, initial_state)

        for m in range(2 ** block_size):
            m = matasano.util.bytes_for_int(m, block_size)
            dummy_h = weak_hash(m, state=dummy_state)

            if dummy_h in single_block_hashes:
                return dummy_h, single_block_hashes[dummy_h], dummy + m

        assert False, "Something went wrong while finding a collision."

    def make_expandable_message(k: int, initial_state: bytes=b'') -> typing.Tuple[bytes, typing.List]:
        """
        Generate a (k, k + 2 ** (k − 1)) expandable message.

        :param k: The fixed length parameter.
        :param initial_state: The initial state of the hash function.
        :return: The final state of the hash function and the expandable message.
        """
        expandable = []

        for i in range(1, k + 1):
            initial_state, single_block_message, dummy_message = \
                alpha_collision(2 ** (k - i), initial_state)

            assert len(single_block_message) == block_size
            assert len(dummy_message) == (2 ** (k - i) + 1) * block_size

            expandable.append((single_block_message, dummy_message))

        assert len(expandable) == k
        return initial_state, expandable

    def produce_message(expandable: typing.List, desired_len: int) -> bytes:
        """
        Produce a message of desired length, starting from the expandable message.

        :param expandable: The list of k tuples forming the expandable message.
        :param desired_len: The desired message length.
        :return: A message of the desired length.
        """
        assert expandable
        assert len(expandable[0][0]) == block_size

        k = len(expandable)
        assert k <= desired_len // block_size <= k + 2 ** k - 1

        message = b''
        for i, e in enumerate(expandable):
            if len(message) + len(e[1]) + (len(expandable) - i - 1) * block_size <= desired_len:
                message += e[1]
            else:
                message += e[0]

        assert len(message) == desired_len, \
            "Produced a message of length {}, different from desired length ({})".format(len(message), desired_len)
        return message

    k = 8
    original_message = matasano.util.random_bytes_range(2 ** k)
    assert len(original_message) % block_size == 0

    initial_state = b''
    hash_to_length = {}  # Map each intermediate hash to the processed message length
    for i in range(0, len(original_message), block_size):
        initial_state = weak_hash(original_message[i:i + block_size], initial_state)
        if i > k * block_size:
            hash_to_length[initial_state] = i
    assert initial_state == weak_hash(original_message)

    final_state, expandable_message = make_expandable_message(k)
    assert len(expandable_message) == k
    assert \
        weak_hash(b''.join(e[0] for e in expandable_message)) == weak_hash(b''.join(e[1] for e in expandable_message))

    bridge_index = -1
    for bridge in range(2 ** block_size):  # Find a collision against a single block
        bridge = matasano.util.bytes_for_int(bridge, length=16)
        h = weak_hash(bridge, final_state)  # Starting from the final state of the exp. message

        if h in hash_to_length:
            bridge_index = hash_to_length[h]
            break
    else:
        assert False, "Something went wrong while finding bridge collision"

    second_pre_image = produce_message(expandable_message, bridge_index)
    assert weak_hash(second_pre_image + bridge) in hash_to_length

    collision = second_pre_image + bridge + original_message[bridge_index + len(bridge):]

    # Make sure that colliding message has same length.
    assert len(original_message) == len(collision), \
        "Original message length {} - Colliding message length {}".format(len(original_message), len(collision))

    print("Original message: {}.".format(original_message))
    print("Colliding message: {}.".format(collision))

    return weak_hash(original_message) == weak_hash(collision)


@challenge
def fiftyfour():
    """http://cryptopals.com/sets/7/challenges/54/"""
    weak_hash = matasano.hash.weak_iterated_hash
    block_size = 16
    k = 4

    committed_length = 128  # Will be put in the final block of the hash

    prediction = b'Message in a bot'
    assert len(prediction) % block_size == 0

    print("Building leaves of the tree...")
    leaves = {
        m: weak_hash(m)
        for m in (matasano.util.bytes_for_int(i, block_size) for i in range(2 ** k))
    }
    assert len(leaves) % 2 == 0

    def find_pair_collision(iv_1: bytes, iv_2: bytes) -> typing.Tuple[bytes, bytes, bytes]:
        """
        Given two initial vector, find two messages that hashed collide to the same value.

        :param iv_1: The first initial vector.
        :param iv_2: The second initial vector.
        :return: The two new message.
        """
        for i in range(2 ** block_size):
            i = matasano.util.bytes_for_int(i, length=block_size)
            for j in range(2 ** block_size):
                j = matasano.util.bytes_for_int(j, block_size)

                h = weak_hash(i, iv_1)
                if h == weak_hash(j, iv_2):
                    return i, j, h

                h = weak_hash(j, iv_1)
                if h == weak_hash(i, iv_2):
                    return j, i, h

        assert False, "Something went wrong while finding collisions."

    tree = []
    previous_level = []
    next_level = []

    print("Building level 1 of the tree...")
    while len(leaves):
        a, b = leaves.popitem(), leaves.popitem()
        previous_level += [a, b]
        a, b, h = find_pair_collision(a[1], b[1])
        next_level.append(((a, b), h))
    assert weak_hash(previous_level[0][0] + next_level[0][0][0]) == next_level[0][1]

    assert len(previous_level) % 2 == 0
    assert len(next_level) % 2 == 0
    assert len(previous_level) == len(next_level) * 2
    tree.append(previous_level)
    tree.append(next_level)

    previous_level = next_level
    n = 2

    while len(previous_level) >= 2:
        print("Building level {} of the tree...".format(n))
        next_level = []

        for i in range(0, len(previous_level), 2):
            a, b = previous_level[i], previous_level[i + 1]
            a, b, h = find_pair_collision(a[1], b[1])
            next_level.append(((a, b), h))

        assert len(previous_level) == len(next_level) * 2
        tree.append(next_level)
        previous_level = next_level
        n += 1

    assert len(tree[-1]) == 1

    glue_blocks_len = committed_length - len(prediction) - (block_size * (len(tree) - 1))
    assert glue_blocks_len > 0, "Please specify a longer predicted message length."

    committed_length_b = matasano.util.bytes_for_int(committed_length, block_size)
    print("Generating final padded hash...")
    # This will be released before the start of the season.
    predicted_hash = weak_hash(committed_length_b, tree[-1][0][1])

    leaves = {l[1]: i for i, l in enumerate(tree[0])}  # Map hashes to leaf indexes
    message, h = b'', -1

    while True:
        glue = matasano.util.random_bytes_range(glue_blocks_len)
        message = prediction + glue
        h = weak_hash(message)

        if h in leaves:
            break

    leaf_index = leaves[h]
    assert weak_hash(message) == tree[0][leaf_index][1]
    print("Found colliding leaf index: {}. Traversing tree from leaf to root...".format(leaf_index))

    colliding_message = message
    for i in range(1, len(tree)):
        colliding_message += tree[i][leaf_index // (2 ** i)][0][leaf_index // (2 ** (i - 1)) % 2]
    assert len(colliding_message) == committed_length

    return predicted_hash == weak_hash(committed_length_b, weak_hash(colliding_message))


@challenge
def fiftyfive():
    """http://cryptopals.com/sets/7/challenges/55/"""
    compress = matasano.hash.md4_compress

    ith = matasano.util.ith_bit
    lr = matasano.util.left_rotate
    rr = matasano.util.right_rotate

    a_0, b_0, c_0, d_0 = matasano.hash.md4_initial_state

    def _f(_x, _y, _z):
        return _x & _y | ~_x & _z

    def _s1(_a, _b, _c, _d, k, s, big_x):
        return matasano.util.left_rotate(_a + _f(_b, _c, _d) + big_x[k], s)

    m = [
        0x4d7a9c83, 0x56cb927a, 0xb9d5a578, 0x57a7a5ee,
        0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f,
        0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8,
        0x45dd8e31, 0x97e31fe5, 0x2794bf08, 0xb9e8c3e9
    ]
    print("Original message: {}.".format(m))

    m_b = matasano.util.to_little_endian_unsigned_ints(m)
    assert len(m_b) == 64

    truth = compress(m_b)
    assert truth == [0x5f5c1a0d, 0x71b36046, 0x1b5435da, 0x9b0d807a]

    a_1 = _s1(a_0, b_0, c_0, d_0, 0, 3, m)
    d_1 = _s1(d_0, a_1, b_0, c_0, 1, 7, m)

    d_1_m = d_1 ^ (lr(ith(d_1, 6), 6)) ^ \
        (lr(ith(d_1, 7) ^ ith(a_1, 7), 7)) ^ \
        (lr(ith(d_1, 10) ^ ith(a_1, 10), 10))

    collision = m[:]
    collision[1] = (rr(d_1_m, 7)) - d_0 - _f(a_1, b_0, c_0)
    print("Colliding message: {}.".format(collision))

    collision_b = matasano.util.to_little_endian_unsigned_ints(m)
    digest = compress(collision_b)
    print("Digest: {}.".format(digest))

    # For the moment, I stop here, with the "Single-Step Modification".
    # In the future, anyway, I may come back to implement the "Multi-Step Modification".

    return collision != m and truth == digest


def main():
    """
    Read the argument from the command line,
    and execute the related challenge.
    """
    _num2words = {
        1: 'one', 2: 'two', 3: 'three', 4: 'four', 5: 'five',
        6: 'six', 7: 'seven', 8: 'eight', 9: 'nine', 10: 'ten',
        11: 'eleven', 12: 'twelve', 13: 'thirteen', 14: 'fourteen',
        15: 'fifteen', 16: 'sixteen', 17: 'seventeen', 18: 'eighteen',
        19: 'nineteen', 20: 'twenty', 30: 'thirty', 40: 'forty',
        50: 'fifty', 60: 'sixty', 70: 'seventy', 80: 'eighty',
        90: 'ninety', 0: 'zero'
    }

    problem_meta_var = "problem_number"

    def _number_to_words(n: int) -> str:
        """
        Given a number, convert it to respective words.

        :param n: Number to be converted. Must be 0 <= n < 100
        :return: The number convert to its word representation.
        """
        assert 0 <= n < 100
        try:
            return _num2words[n]
        except KeyError:
            try:
                return _num2words[n - n % 10] + _num2words[n % 10]
            except KeyError:
                raise Exception('Number out of range')

    def _create_parser() -> argparse.ArgumentParser:
        """
        Create the command line argument parser.

        :return: The command line argument parser for this module.
        """
        parser = argparse.ArgumentParser(
            description='Matasano Crypto-Challenge solver.'
        )

        parser.add_argument(
            problem_meta_var,
            metavar=problem_meta_var,
            type=int,
            help='the number of the problem to be solved'
        )

        return parser

    colorama.init()

    command_line_parser = _create_parser()
    args = vars(command_line_parser.parse_args())

    problem_number = args[problem_meta_var]
    assert 1 <= problem_number <= 56

    problem = globals().get(_number_to_words(problem_number), None)
    assert problem is not None, \
        "Sorry, not yet implemented."

    assert callable(problem)
    problem()
