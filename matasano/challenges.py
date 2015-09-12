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
import matasano.public

import base64
import binascii
import argparse
import io
import sys
import contextlib
import functools
import colorama
import pkg_resources

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
