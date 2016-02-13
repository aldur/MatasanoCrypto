#!/usr/bin/env/ python
# encoding: utf-8

"""
The oracle related stuff.
Random generations, games, and so on.
"""

import random
import base64
import binascii
import abc
import re
import collections
import time
import functools
import http.server
import http.client
import urllib.parse
import threading
import socketserver
import typing

import matasano.blocks
import matasano.util
import matasano.prng
import matasano.mac
import matasano.math
import matasano.hash
import matasano.public

__author__ = 'aldur'


class CheatingException(Exception):
    """
    Thrown when the oracle detects that the attacker is trying to cheat.
    """
    pass


class BadAsciiPlaintextException(Exception):
    """
    Thrown if an error occurs while decoding plaintext to ASCII.
    """

    def __init__(self, recovered_plaintext: bytes):
        super().__init__()
        self.recovered_plaintext = recovered_plaintext


class Oracle(object):
    """
    The base oracle abstract class.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def challenge(self, *args: bytes) -> bytes:
        """
        Challenge the oracle.
        Send him some bytes,
        and it will return some other bytes.
        Usually this function can be called only once.

        :param args: An iterable of bytes.
        :return: Some bytes.
        """
        return random.choice(args) if args else bytes()

    @abc.abstractmethod
    def guess(self, guess: bool) -> bool:
        """
        Given a guess, return true if correct.
        Usually this function can be called only once.

        :param guess: The guess done by the attacker.
        :return: True if the attacker correctly guessed.
        """
        return guess

    @abc.abstractmethod
    def experiment(self, *args: bytes) -> bytes:
        """
        Experiment with the oracle (when possible).
        Usually this function can be called how many times you need.

        :param args: An iterable of bytes.
        :return: Some bytes.
        """
        return random.choice(args) if args else bytes()


class OracleAesEcbCbc(Oracle):
    """An encryption oracle that randomly encrypts with AES ECB or AES CBC.

    Choose at random between AES ECB and AES CBC (by tossing a coin).
    Generate a random key.
    Add padding before and after b.
    Encrypt b.
    """

    def __init__(self):
        """
        Choose the cipher to use.
        """
        super(Oracle, self).__init__()
        self.cipher = matasano.blocks.aes_ecb if \
            random.random() >= 0.5 \
            else matasano.blocks.aes_cbc
        self._truth = self.cipher == matasano.blocks.aes_ecb  # using ECB encryption
        self._challenge_done = False
        self._guess_done = False

    def challenge(self, *args: bytes) -> bytes:
        """
        Generate a random key.
        Add padding before and after the first block.
        Encrypt the block.

        :param args: The block buffer to be encrypted.
            Must be a multiple of 16.
            This implementation encrypts the first one
            and ignore the others.
        :returns: An encryption of b.
        """
        assert args
        assert args[0]

        if self._challenge_done:
            raise CheatingException("Challenge can only be called once.")
        self._challenge_done = True

        b = args[0]
        key = matasano.util.random_aes_key()

        # Add some randomness
        b = matasano.util.random_bytes_random_range(5, 10) + b + matasano.util.random_bytes_random_range(5, 10)
        # Pad if necessary
        b = matasano.blocks.pkcs_7(b, 16)

        ciphertext = self.cipher(key, b)
        if isinstance(ciphertext, bytes) or isinstance(ciphertext, bytearray):
            return ciphertext
        else:
            return ciphertext[0]

    def guess(self, guess: bool) -> bool:
        """
        Return true if the attacker correctly guesses.
        :param guess: True if attacker thinks encryption is
        ECB, false otherwise.
        :return: True if attacker correctly guesses.
        """
        if self._guess_done:
            raise CheatingException("Attackers can only guess once")
        self._guess_done = True
        return guess == self._truth

    def experiment(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide experiments.
        :param args: An iterable of bytes.
        """
        return super().experiment(args)


class OracleProfileForUser(Oracle):
    """
    An encryption oracle that provide information about a user.
    Specifically, given an email address, it produces data.
    Then encode it as key-values, and finally encrypts it.
    """

    """Possible roles for each user."""
    _roles = ("admin", "user")

    def __init__(self):
        super(Oracle, self).__init__()
        self._key = matasano.util.random_aes_key()
        self._last_uid = -1
        self._has_guessed = False

    def _build_profile(self, mail: str) -> str:
        """
        Build the profile dictionary for a user.
        The dictionary is deterministic.
        The role will always be user, and the IDs follow a monotonic growing function.

        :param mail: The email of the users. Meta characters "&" and "=" will be removed.
        :return:
        """
        assert mail
        assert re.match(
            #  This can't be as strong as I'd like.
            r"^[^@\.]+@[^@\.]+\.[^@\.]{2,4}$",
            mail
        ), "Specified mail is invalid."

        mail = mail.strip("&=")
        self._last_uid += 1
        d = collections.OrderedDict()
        d["email"] = mail
        d["uid"] = self._last_uid
        d["role"] = OracleProfileForUser._roles[1]

        return matasano.util.dictionary_to_kv(
            collections.OrderedDict(d)
        )

    def experiment(self, mail: bytes) -> bytes:
        """
        Build a profile from the mail, encode it and encrypt it by using AES ECB.
        Then return it.

        :param mail: The mail whose profile must be created.
        """
        profile = self._build_profile(mail.decode("ascii"))
        return matasano.blocks.aes_ecb(
            self._key,
            matasano.blocks.pkcs_7(profile.encode("ascii"), 16)
        )

    def guess(self, guess: bytes) -> bool:
        """
        Check whether the attacker has forged an admin user.

        :param guess: An encoded and encrypted user profile.
        :raise CheatingException: If called more than once.
        :return: True on admin user forging.
        """
        if self._has_guessed:
            raise CheatingException("Attacker can only guess once!")
        self._has_guessed = True

        encoded_profile = matasano.blocks.aes_ecb(
            self._key,
            guess,
            decrypt=True
        ).decode("ascii")
        profile = matasano.util.key_value_parsing(encoded_profile)
        return profile["role"].strip() == OracleProfileForUser._roles[0]

    def challenge(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide a challenge.

        :param args: An iterable of bytes.
        """
        return super().challenge(args)


class OracleBitflipping(Oracle):
    """
    An encryption oracle that takes an arbitrary string,
    prepends it with:
        "comment1=cooking%20MCs;userdata="
    And appends to the result the string:
        ";comment2=%20like%20a%20pound%20of%20bacon"

    Before processing the string it escapes the meta characters
    "=" and ";".

    The attacker's goal is to forge a string such that,
    once decrypted, it contains ";admin=true"

    :param encryption_function: The function used to encrypt.
    :param needs_padding: Whether to pad the plaintext before encryption.
    """

    def __init__(self, encryption_function, needs_padding: bool=False):
        super(Oracle, self).__init__()
        assert encryption_function

        """
        Store the encryption function.
        """
        self.needs_padding = needs_padding
        self.encryption_function = encryption_function

        """
        This is a consistent AES key.
        It is the same for the whole module lifetime,
        but it's hidden from anyone (kinda)
        """
        self._consistent_key = matasano.util.random_aes_key()

        """
        The string prefix.
        """
        self._prefix = b"comment1=cooking%20MCs;userdata="

        """
        The string suffix.
        """
        self._suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

        """
        The meta-characters to be escaped.
        """
        self._meta = "=;"

        self._guess = False

    def challenge(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide a challenge.
        :param args: An iterable of bytes.
        """
        return super().challenge(args)

    def experiment(self, input_string: bytes) -> bytes:
        """
        Escape the meta-character from the input string.
        Append the prefix and the suffix.
        Pad the result.
        Encrypt it, and return it to the caller.

        :param input_string: The input string.
        """
        input_string = matasano.util.escape_metas(
            input_string.decode("ascii"), self._meta
        ).encode("ascii")
        input_string = self._prefix + input_string + self._suffix

        if self.needs_padding:
            input_string = matasano.blocks.pkcs_7(input_string, 16)

        ciphertext, _ = self.encryption_function(
            self._consistent_key,
            input_string
        )
        return ciphertext

    def guess(self, guess: bytes) -> bool:
        """
        Check whether the attacker has forged an admin user.

        :param guess: An encoded and encrypted user profile.
        :raise CheatingException: If called more than once.
        :return: True on admin user forging.
        """
        if self._guess:
            raise CheatingException("Attackers can only guess once!")
        self._guess = True

        payload, _ = self.encryption_function(
            self._consistent_key,
            guess,
            decrypt=True
        )
        return b";admin=true;" in payload


class OracleByteAtATimeEcb(Oracle):
    """
    An encryption oracle that encrypts each block with the
    same fixed key.
    Before encryption, he pads each block with a constant string,
    unknown to the caller.
    The attacker's goal are:
        - guess the block size of encryption, as used by the oracle (16)
        - guess the AES encryption mode (ECB)
        - discover the unknown fixed string, one byte at a time.
    """

    def __init__(self):
        super(Oracle, self).__init__()
        """
        This is a consistent AES key.
        It is the same for the whole oracle lifetime,
        but it's hidden from anyone (kinda)
        """
        self._consistent_key = matasano.util.random_aes_key()
        """
        And this is the unknown string, that the attacker has to find.
        """
        self._unknown_string = base64.b64decode(
            b"""Um9sbGluJyBpbiBteSA1LjAKV2l0a
            CBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ
            2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEa
            WQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"""
        )

        self._guess = False

    def challenge(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide a challenge.
        :param args: An iterable of bytes.
        """
        return super().challenge(args)

    def guess(self, guess: bytes) -> bool:
        """
        Compare the attacker's guess against the unknown string.

        :param guess: The attacker's guess.
        :raise CheatingException: If called more than once.
        :return: True if the guess is correct.
        """
        assert guess

        if self._guess:
            raise CheatingException("Attackers can only guess once.")
        self._guess = True

        return guess == self._unknown_string

    def experiment(self, *args: bytes) -> bytes:
        """
        Return an encryption of the first block of args,
        padded with the fixed unknown string.
        :param args: An iterable of buffers to be encrypted.
        :return: An encryption of the first block.
        """
        assert args
        assert args[0]

        return matasano.blocks.aes_ecb(
            self._consistent_key,
            matasano.blocks.pad_with_buffer(
                args[0],
                self._unknown_string
            )
        )


class OracleHarderByteAtATimeEcb(OracleByteAtATimeEcb):
    """
    Same as OracleByteAtATimeEcb, but prefix the user string with
    a fixed, randomly generated one.
    """

    def __init__(self):
        super().__init__()
        """
        The fixed string prefix.
        """
        self._prefix = matasano.util.random_bytes_random_range(1, 32)

    def experiment(self, *args: bytes) -> bytes:
        """
        Return an encryption of the first block of args,
        prefixed with the static random string and
        padded with the fixed unknown string.
        :param args: An iterable of buffers to be encrypted.
        :return: An encryption of the first block.
        """
        assert args
        assert args[0]

        b = matasano.blocks.pad_with_buffer(
            self._prefix + args[0],
            self._unknown_string
        )
        return matasano.blocks.aes_ecb(
            self._consistent_key,
            b
        )


class OracleCBCPadding(Oracle):
    """
    Choose at random between one of the random possible strings.
    Pad it.
    CBC encrypt it with a fixed and random AES key.
    Return to the caller the ciphertext and the IV.

    Furthermore, provide a function that takes a ciphertext,
    decrypts it and returns True whether the acquired plaintext
    has a valid padding.

    The attacker's goal is to discover the encrypted string.
    """

    def __init__(self, strings_path: str):
        """
        Init the oracle.
        Generate a random AES key and pick at random
        on of the possible strings inside the string file.

        :param strings_path: The path to the string file.
        """
        super(Oracle, self).__init__()
        self._consistent_key = matasano.util.random_aes_key()

        with open(strings_path, "rb") as strings:
            s = random.choice(strings.readlines()).rstrip()
            self._hidden_string = matasano.blocks.pkcs_7(s, 16)

        self._guessed = False

    def guess(self, guess: bytes) -> bool:
        """
        Check whether the bytes given by the attacker match
        our hidden string.
        :param guess: The attacker's guess
        """
        assert guess

        if self._guessed:
            raise CheatingException("Attackers can only guess once.")
        self._guessed = True

        return guess == self._hidden_string

    def challenge(self) -> tuple:
        """
        Return to the caller a CBC encryption of the hidden string.
        :return The encryption and the IV.
        """
        ciphertext, iv = matasano.blocks.aes_cbc(
            self._consistent_key,
            self._hidden_string,
            random_iv=True
        )
        return ciphertext, iv

    def experiment(self, iv: bytes, b: bytes) -> bool:
        """
        Check whether the given bytes are correctly padded,
        once decrypted by using the given IV.

        :param iv: The IV to be used.
        :param b: The bytes to be checked.
        """
        assert iv
        assert b
        assert len(b) % 16 == 0

        plaintext, _ = matasano.blocks.aes_cbc(
            self._consistent_key,
            b,
            iv=iv,
            decrypt=True
        )

        try:
            matasano.blocks.un_pkcs_7(plaintext, 16)
        except matasano.blocks.BadPaddingException:
            return False
        else:
            return True


class OracleFixedNonceCTR(Oracle):
    """
    An encryption oracle that takes a list of
    base64 encoded strings, decodes them and
    encrypts them by using AES CTR and a fixed key.

    The attacker's goal is to break the encryption,
    i.e. to discover the strings.
    """

    def __init__(self, strings_path: str):
        """
        Init the oracle.
        Generate a random AES key and
        read the strings.

        :param strings_path: The path to the strings file.
        """
        super(Oracle, self).__init__()
        self._consistent_key = matasano.util.random_aes_key()

        with open(strings_path, "rb") as buffers:
            self._buffers = tuple(
                base64.b64decode(s.rstrip()) for s in buffers
            )

        self._guessed = False

    def challenge(self) -> tuple:
        """
        Encrypt the strings and return them to the caller.

        :return A tuple of encrypted strings.
        """
        return tuple(
            matasano.blocks.aes_ctr(
                self._consistent_key,
                b
            )[0] for b in self._buffers
        )

    def experiment(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide experiments.
        :param args: An iterable of bytes.
        """
        return super().experiment(args)

    def guess(self, guess: tuple) -> bool:
        """
        Check whether the guess is equal to the stored buffers.
        Only check the prefix that is common to all the strings,
        otherwise we'd be requiring the attacker to blind guess
        the longer strings.

        :param guess: The attacker's guess.
        """
        assert guess

        min_len = len(min(self._buffers, key=lambda b: len(b))) + 1
        return len(guess) == len(self._buffers) and all(
            guess[i][:min_len].lower() == self._buffers[i][:min_len].lower()
            for i, _ in enumerate(guess)
        )


class OracleMT19937Seed(Oracle):
    """
    This oracle will deliver the challenge in the following way:
    - wait a random number of seconds
    - seed the MT_PRNG with the Unix timestamp
    - wait a random number of seconds
    - return to the caller the first generated number

    The attacker's goal is to guess the seed.
    """

    def __init__(
            self,
            sleep_min: int=40,
            sleep_max: int=100
    ):
        super().__init__()
        self._seed = None
        self._guessed = False
        self.sleep_min = sleep_min
        self.sleep_max = sleep_max

    def challenge(self) -> int:
        """
        Deliver the challenge to the caller.
        :return: The first output of the MT PRNG.
        """
        time.sleep(
            random.randint(self.sleep_min, self.sleep_max)
        )
        self._seed = int(time.time())
        mt_prng = matasano.prng.MT19937(self._seed)
        time.sleep(
            random.randint(self.sleep_min, self.sleep_max)
        )
        return mt_prng.extract_number()

    def guess(self, guess: int) -> bool:
        """
        Compare the caller's guess with the stored seed.
        :param guess: The attacker's guess.
        :return: True if the guess is correct.
        """
        assert self._seed

        if self._guessed:
            raise CheatingException(
                "You can only guess once!"
            )

        self._guessed = True
        return guess == self._seed

    def experiment(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide experiments.
        :param args: An iterable of bytes.
        """
        return super().experiment(args)


class OracleMT19937Clone(Oracle):
    """
    By using an MT PRNG, generate 624 random outputs
    (i.e. output the MT internal state).

    The attacker's goal is to clone the state generator,
    by using the previously output state.
    """

    def __init__(self):
        super().__init__()
        self._mt_prng = matasano.prng.MT19937(
            int(time.time())
        )
        self._guessed = False

    def guess(self, guess: list) -> bool:
        """
        Compare the attacker's guess with the next
        10 outputs of the PRNG.

        :param guess: The attacker's guess about the next generated numbers.
        :return: True if the guess is correct.
        :raise CheatingException: If called more than once.
        """
        assert guess

        if self._guessed:
            raise CheatingException(
                "You can only guess once!"
            )

        self._guessed = True

        truth = [
            self._mt_prng.extract_number()
            for _ in range(10)
        ]
        assert len(truth) == len(guess)
        return all(truth[i] == g for i, g in enumerate(guess))

    def challenge(self) -> list:
        """
        Return a list of the first 624
        randomly generated numbers to the caller.

        :return: The first 624 randomly generated numbers.
        """
        challenge = tuple(
            self._mt_prng.extract_number()
            for _ in range(624)
        )

        assert len(challenge) == 624
        return challenge

    def experiment(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide experiments.
        :param args: An iterable of bytes.
        """
        return super().experiment(args)


class OracleMT19937Stream(Oracle):
    """
    Encrypt a string of the following form:
        <random_number_of_bytes> || AAA...AAA (14 As)
    The encryption takes places through MT19937-generated numbers
    used as key stream.

    The attacker's goal is to discover the MT19937 seed
    (16 bits, by definition).
    """

    def __init__(self):
        super().__init__()
        self._seed = random.randint(0, 2 ** 16 - 1)
        self.known_plaintext = b"A" * 16
        self._plaintext = bytes(
            matasano.util.random_bytes_random_range(
                1, random.randint(2, 10)
            )
        ) + self.known_plaintext

        self._guessed = False

    def challenge(self) -> bytes:
        """
        Return to the caller the encryption of the plaintext.

        :return: The encryption of the hidden plaintext.
        """
        return matasano.blocks.mt19937_stream(
            self._seed,
            self._plaintext
        )

    def guess(self, guess: int) -> bool:
        """
        Compare the attacker's guess against the stored seed.

        :param guess: The attacker's guessed seed.
        :return: True whether the attack is successful.
        """
        if self._guessed:
            raise CheatingException(
                "You can only guess once."
            )

        self._guessed = True
        return guess == self._seed

    def experiment(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide experiments.
        :param args: An iterable of bytes.
        """
        return super().experiment(args)


class OracleRandomAccessCTR(Oracle):
    """
    Generate a random AES key.
    Encrypt specified plaintext.
    Expose a function to edit a single portion of the plaintext.

    The attacker's goal is to discover the stored plaintext.
    """

    def __init__(self, plaintext: bytes):
        super().__init__()
        assert plaintext

        self._consistent_key = matasano.util.random_aes_key()
        self._original_plaintext = plaintext
        self._plaintext = bytearray(plaintext)
        self._guessed = False

    def guess(self, guess: bytes) -> bool:
        """
        Check whether the attacker's guess is correct.

        :param guess: The attacker's guess.
        :return: True if attacker correctly guesses.
        """
        assert guess

        if self._guessed:
            raise CheatingException(
                "You can only guess once."
            )

        self._guessed = True
        return guess == self._original_plaintext

    def challenge(self) -> bytes:
        """
        Return the stored ciphertext to the caller.
        """
        return matasano.blocks.aes_ctr(
            self._consistent_key, bytes(self._plaintext)
        )[0]

    def experiment(self, offset: int, new_char: int) -> bytes:
        """
        Modify the plaintext character at offset position,
        with new_char.
        Return the new ciphertext.

        :param offset: The offset of the byte to be modified.
        :param new_char: The replacement byte.
        """
        assert 0 <= new_char <= 255
        assert 0 <= offset < len(self._plaintext), \
            "Wrong offset specified."

        self._plaintext[offset] = new_char
        return self.challenge()


class OracleCBCKeyIV(Oracle):
    """
    Encrypt by using AES CBC and a random
    sequence of bytes both as key and as IV.

    The attacker's goal is to discover the key.
    """

    def __init__(self):
        super().__init__()
        self._consistent_key = matasano.util.random_aes_key()

        self._guessed = False

    def guess(self, guess: bytes) -> bool:
        """
        Compare the attacker's guess on the key against
        the stored one.

        :param guess: The attacker's guess.
        """
        if self._guessed:
            raise CheatingException(
                "You can only guess once."
            )
        self._guessed = True
        return self._consistent_key == guess

    def experiment(self, ciphertext: bytes) -> str:
        """
        Decrypt the ciphertext and decode it to ascii.

        :param ciphertext: The ciphertext to be decrypted.
        :return: The decrypted and decoded ciphertext.
        """
        assert len(ciphertext) % 16 == 0

        coded_plaintext, _ = matasano.blocks.aes_cbc(
            self._consistent_key,
            ciphertext,
            decrypt=True,
            iv=self._consistent_key
        )

        error = False
        plaintext = ""
        for i in range(len(coded_plaintext) // 16):
            b = coded_plaintext[matasano.blocks.bytes_in_block(16, i)]
            try:
                plaintext += b.decode("ascii")
            except UnicodeDecodeError:
                error = True

        if error:
            raise BadAsciiPlaintextException(coded_plaintext)

        return plaintext

    def challenge(self) -> bytes:
        """
        Encrypt a random ascii plaintext exactly three blocks long.

        :return: The encryption of the plaintext.
        """
        return matasano.blocks.aes_cbc(
            self._consistent_key,
            bytes(
                random.randint(0, 127) for _ in range(16 * 3)
            ),
            iv=self._consistent_key
        )[0]


class OracleKeyedMac(Oracle):
    """
    An oracle that generates a MAC for a given message,
    by using the secret_key_prefixed and the specified MAC function.

    The attacker's goal is to forge a valid MAC for a
    never seen message.
    """

    def __init__(self, mac_function):
        super().__init__()
        self.mac_function = mac_function
        self._secret_key = matasano.util.random_aes_key()
        self.key_len = len(self._secret_key)  # An attacker could brute-force it
        self._messages = set()

    def challenge(self, message: bytes) -> bytes:
        """
        Return a MAC of the message.

        :param message: The input message.
        :return: A MAC of the message.
        """
        self._messages.add(message)
        return self.mac_function(
            self._secret_key,
            message
        )

    def guess(self, message: bytes, guess: bytes) -> bool:
        """
        Check if the given MAC is a valid signature
        of the message.

        :param message: A never-seen-before message.
        :param guess: The attacker-forged MAC for the message.
        """
        if message in self._messages:
            raise CheatingException(
                "You have to forge a MAC for a new message!"
            )

        truth = self.challenge(
            message
        )

        return truth == guess

    def experiment(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide experiments.
        :param args: An iterable of bytes.
        """
        return super().experiment(args)


class OracleSHA1KeyedMac(OracleKeyedMac):
    """
    An Oracle that generates a MAC by using the SHA1 hash function,
    prefixed with a key.
    """

    def __init__(self):
        super().__init__(matasano.mac.sha1_secret_prefix)


class OracleMD4KeyedMac(OracleKeyedMac):
    """
    An Oracle that generates a MAC by using the MD4 hash function,
    prefixed with a key.
    """

    def __init__(self):
        super().__init__(matasano.mac.md4_secret_prefix)


class OracleRemoteSHA1HMac(Oracle):
    """
    An oracle that forwards the SHA1_HMAC
    signature checking to a remote server.
    """
    sleep_time = 0.005
    mac_function = matasano.mac.hmac_sha1

    @staticmethod
    def insecure_check(
            key: bytes,
            message: bytes,
            signature: bytes
    ) -> bool:
        """
        Check the provided signature against the correct one.

        :param key: The key used by the MAC function.
        :param message: The message to be verified.
        :param signature: The provided signature.
        :return: True if the signature is correct.
        """
        truth = OracleRemoteSHA1HMac.mac_function(
            key,
            message
        )

        if len(truth) != len(signature):
            return False

        for i, b in enumerate(truth):
            if b != signature[i]:
                return False
            time.sleep(OracleRemoteSHA1HMac.sleep_time)

        return True

    class SignatureCheckHandler(http.server.BaseHTTPRequestHandler):
        """
        Simple HTTP handler that gets the needed parameters
        from the GET request and checks that the contained signature
        is indeed valid.
        """

        def __init__(self, key: bytes, *args):
            self._key = key
            super(http.server.BaseHTTPRequestHandler, self).__init__(*args)

        def do_GET(self):
            """
            Handle GET requests.
            """
            params = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query
            )

            if "file" not in params or "signature" not in params:
                self.send_response(http.client.INTERNAL_SERVER_ERROR)
                self.end_headers()
                return

            status = http.client.OK if OracleRemoteSHA1HMac.insecure_check(
                self._key,
                params["file"][0].encode("ascii"),
                bytearray.fromhex(
                    params["signature"][0]
                )
            ) else http.client.BAD_REQUEST
            self.send_response_only(status)
            self.end_headers()

    class ThreadingSimpleServer(
        socketserver.ThreadingMixIn,
        http.server.HTTPServer
    ):
        """
        A simple threaded HTTP server.
        """
        pass

    def __init__(self):
        super().__init__()
        self._remote_port = 8000

        self._consistent_key = matasano.util.random_aes_key()

        self.http_thread = None
        self.start_http_server()

        self.connection = http.client.HTTPConnection(
            "localhost",
            self._remote_port
        )

    def start_http_server(self):
        """
        Start the HTTP server in a separate thread.
        """
        httpd = OracleRemoteSHA1HMac.ThreadingSimpleServer(
            ("", self._remote_port),
            lambda *args: OracleRemoteSHA1HMac.SignatureCheckHandler(
                self._consistent_key, *args
            )
        )
        self.http_thread = threading.Thread(
            target=httpd.serve_forever
        )
        self.http_thread.daemon = True
        self.http_thread.start()

    def guess(self, message: bytes, signature: bytes) -> bool:
        """
        Return True whether the attacker has forged a valid signature
        for the message.

        :param message: The message.
        :param signature: The MAC forged by the attacker.
        :return: True on correct forgery.
        """
        truth = OracleRemoteSHA1HMac.mac_function(
            self._consistent_key, message
        )
        return truth == signature

    def challenge(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide a challenge.

        :param args: An iterable of bytes.
        """
        return super().challenge(args)

    def experiment(self, message: bytes, signature: bytes) -> bool:
        """
        Forward the signature verification message to the remote server.
        :param message: The message to be verified.
        :param signature: The MAC.
        """
        self.connection.request(
            "GET",
            "/foo?file={}&signature={}".format(
                message.decode("ascii"),
                binascii.hexlify(signature).decode("ascii")
            )
        )

        response = self.connection.getresponse()

        if response.status == http.client.OK:
            return True
        else:
            return False


class OracleUnpaddedRSARecovery(Oracle):
    
    """
    Decrypt (only once) arbitrary RSA blobs.
    The attacker's challenge is to trick the oracle
    into decrypting an already-seen blob.
    """

    def __init__(self):
        super(OracleUnpaddedRSARecovery, self).__init__()

        self._keys = matasano.public.rsa_keys()
        self._secret = matasano.util.bytes_for_int(
            random.randint(1, self._keys.pub.n)
        )

        self._guessed = False
        self._decrypted = set(self._secret)

    def guess(self, guess: bytes) -> bool:
        """
        Compare the attacker's guess against the hold secret.

        :param guess: The attacker's guess.
        :return: True if the guess is correct.
        """
        if self._guessed:
            raise CheatingException(
                "You can only guess once!"
            )
        self._guessed = True
        return guess == self._secret

    def challenge(self) -> tuple:
        """
        Return to the caller a new ciphertext and the public key.
        """
        return matasano.public.rsa_encrypt(
            self._keys.pub,
            self._secret
        ), self._keys.pub

    def experiment(self, cipher: int) -> bytes:
        """
        Decrypt the cipher and return it to the oracle,
        iff the corresponding plaintext has never been seen.

        :param cipher: The ciphertext to be decrypted.
        :return: The plaintext.
        """
        plaintext = matasano.public.rsa_decrypt(
            self._keys.priv,
            cipher
        )

        if plaintext in self._decrypted:
            raise CheatingException(
                "I won't decrypt this blob again."
            )

        self._decrypted.add(plaintext)
        return plaintext


class OracleRSAPaddedSignatureVerifier(Oracle):

    """
    An oracle that verify RSA signatures.
    Before being signed messages are hashed
    and padded.

    :param message: The message to be discovered by the attacker.
    """

    block_size = 1024 // 8
    pad_function = functools.partial(
        matasano.blocks.pkcs_1_5,
        size=block_size
    )
    hash_function = matasano.hash.SHA1

    def __init__(self, message: bytes):
        super(OracleRSAPaddedSignatureVerifier, self).__init__()
        self._keys = matasano.public.rsa_keys(
            p=matasano.math.random_big_prime(N=2048),
            q=matasano.math.random_big_prime(N=2048),
            e=3
        )
        self._message = message

    def challenge(self) -> tuple:
        """
        Return the message for which a signature
        needs to be forged and the public key used to verify it.
        """
        return self._message, self._keys.pub

    def guess(self, signature: int) -> bool:
        """
        Check the signature provided from the caller.
        Return true if is valid.

        :param signature: The signature provided by the caller.
        :return: True if the signature is valid.
        """
        signed_message = matasano.util.bytes_for_int(
            pow(signature, self._keys.pub.e, self._keys.pub.n),
            byteorder="big"
        )

        this = OracleRSAPaddedSignatureVerifier
        expected_message = this.pad_function(
            this.hash_function(self._message)
        )[1:]  # Technical detail, int to bytes conversion looses leading 0x00

        return expected_message[:this.block_size] in signed_message[:this.block_size]

    def experiment(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide experiments.
        :param args: An iterable of bytes.
        """
        return super().experiment(args)


class OracleDSA(Oracle):

    """
    A oracle holding a DSA public key.
    The attacker's guess is to find the private key.
    """

    def __init__(self, public: matasano.public.DSA_Pub):
        super(OracleDSA, self).__init__()
        self.public_key = public

    def guess(self, guess: int) -> bool:
        """
        Check whether given private key guess is valid.

        :param guess: The attacker's guess on the private key.
        :return: True if the private key generated the public key and the signature.
        """
        y, p, q, g = self.public_key

        if not 0 < guess < q:
            return False

        return pow(g, guess, p) == y

    def challenge(self):
        """
        This oracle doesn't provide a challenge (everything is fixed and public).
        """
        return None

    def experiment(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide experiments.
        :param args: An iterable of bytes.
        """
        return super().experiment(args)


class OracleDSAKeyFromNonce(OracleDSA):

    """
    A oracle holding a known signature for a known message.
    The attacker's goal is to find the DSA private key,
    by brute-forcing the nonce value 0 <= k <= 2 ** 16 - 1.
    """

    hash_function = matasano.hash.SHA1
    message = (
        b"""For those that envy a MC it can be hazardous to your health\n"""
        b"""So be friendly, a matter of life and death, just like a etch-a-sketch\n"""
    )
    assert binascii.hexlify(
        hash_function(message)
    ) == b"d2d0714f014a9784047eaeccf956520045c45265"

    public_key = matasano.public.DSA_Pub(
        int(
            """84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"""
            """abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"""
            """e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"""
            """1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"""
            """bb283e6633451e535c45513b2d33c99ea17""",
            base=16
        ),
        matasano.public.dsa_p,
        matasano.public.dsa_q,
        matasano.public.dsa_g,
    )

    signature = matasano.public.DSA_Signature(
        548099063082341131477253921760299949438196259240,
        857042759984254168557880549501802188789837994940
    )

    hash_to_int = matasano.public.DSA_hash_to_int
    assert hex(hash_to_int(hash_function(message))) == \
        "0xd2d0714f014a9784047eaeccf956520045c45265"

    k_range = range(1, 2 ** 16 - 1)

    def guess(self, guess: int) -> bool:
        """
        Check whether given private key guess is valid.

        :param guess: The attacker's guess on the private key.
        :return: True if the private key generated the public key and the signature.
        """
        return super().guess(guess)

    def challenge(self):
        """
        This oracle doesn't provide a challenge (everything is fixed and public).
        """
        return None

    def experiment(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide experiments.
        :param args: An iterable of bytes.
        """
        return super().experiment(args)


class OracleDSAKeyFromRepeatedNonce(OracleDSA):

    """
    A oracle holding a known set of messages and signatures,
    and a private key.
    The attacker's goal is to find the DSA private key,
    by knowing that some messages have been signed by using
    the same k nonce.
    """

    public_key = matasano.public.DSA_Pub(
        int(
            """2d026f4bf30195ede3a088da85e398ef869611d0f68f07"""
            """13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"""
            """5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"""
            """f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"""
            """f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"""
            """2971c3de5084cce04a2e147821""",
            base=16
        ),
        matasano.public.dsa_p,
        matasano.public.dsa_q,
        matasano.public.dsa_g,
    )

    SignatureForMessage = collections.namedtuple(
        "SignatureForMessage",
        ["msg", "s", "r", "h"]
    )

    def _parse_signatures(self, signatures: str):
        signature_for_messages = list()

        with open(signatures) as signatures_s:
            lines = signatures_s.readlines()
            for i in range(0, len(lines), 4):
                four_lines = lines[i:i + 4]
                msg, s, r, h = four_lines

                msg = msg[len("msg: "):].rstrip("\n")
                s = int(s[len("s: "):].rstrip("\n"))
                r = int(r[len("r: "):].rstrip("\n"))
                h = int(h[len("m: "):].rstrip("\n"), 16)

                signature_for_messages.append(
                    type(self).SignatureForMessage(msg, s, r, h)
                )

        return signature_for_messages

    def __init__(
            self,
            public: matasano.public.DSA_Pub,
            signatures: str
    ):
        super(OracleDSAKeyFromRepeatedNonce, self).__init__(public)
        self.signatures_for_messages = self._parse_signatures(signatures)

    def challenge(self) -> list:
        """
        Return to the caller the list of messages and related signatures.
        """
        return self.signatures_for_messages

    def experiment(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide experiments.
        :param args: An iterable of bytes.
        """
        return super().experiment(args)

    def guess(self, guess: int) -> bool:
        """
        Check whether given private key guess is valid.

        :param guess: The attacker's guess on the private key.
        :return: True if the private key generated the public key and the signature.
        """
        return super(OracleDSAKeyFromRepeatedNonce, self).guess(guess)


class OracleRSAParity(Oracle):

    """
    This oracle is holding a hidden message.
    It provides a function to check the parity
    of any given plaintext from any given ciphertext.
    The attacker's guess is to discover the message.

    :param message: The hidden message.
    """

    def __init__(self, message: bytes):
        super().__init__()

        self._message = message
        self._keys = matasano.public.rsa_keys()

    def challenge(self) -> tuple:
        """
        Return an encryption of the message to the caller.
        :return: An encryption of the hidden message and the public key.
        """
        return matasano.public.rsa_encrypt(
            self._keys.pub,
            self._message
        ), self._keys.pub

    def experiment(self, cipher: int) -> bool:
        """
        Return true if the plaintext form the cipher is even.
        :param cipher: The cipher to be tested.
        :return: The parity of the derived plaintext.
        """
        d, n = self._keys.priv
        return pow(cipher, d, n) % 2 == 0

    def guess(self, guess: bytes) -> bool:
        """
        Evaluate the attacker's guess.

        :param guess: The attacker's guess on the hidden message.
        :return: True if the guess is correct.
        """
        return self._message == guess


class OracleRSAPadding(Oracle):

    """
    This oracle is holding a hidden message.
    It provides a function to check whether
    any given plaintext from any given ciphertext
    has been correctly PKCS-1.5 padded.
    The attacker's guess is to discover the message.

    :param message: The hidden message.
    """

    def __init__(self, message: bytes):
        super().__init__()

        size = 384
        self._keys = None
        e = 3

        # 128 bits are too weak for the usual getStrongPrime()
        while not self._keys:
            try:
                self._keys = matasano.public.rsa_keys(
                    p=matasano.math.random_big_prime(size),
                    q=matasano.math.random_big_prime(size),
                    e=e
                )
            except ValueError:
                # 3 is not invertible mod fi(n), try again.
                pass

        self.byte_size = size * 2 // 8
        self._message = matasano.blocks.pkcs_1_5(
            message,
            self.byte_size
        )
        assert self._message < self._keys.pub.n

    def challenge(self) -> tuple:
        """
        Return an encryption of the padded message to the caller.
        :return: An encryption of the padded hidden message and the public key.
        """
        e, n = self._keys.pub
        return pow(self._message, e, n), self._keys.pub

    def experiment(self, cipher: int) -> bool:
        """
        Return true if the plaintext form the cipher has been correctly
        PKCS padded.
        :param cipher: The cipher to be tested.
        :return: The padding validity of the plaintext.
        """
        d, n = self._keys.priv

        padded = pow(cipher, d, n)
        try:
            matasano.blocks.un_pkcs_1_5(padded, self.byte_size)
            return True
        except matasano.blocks.BadPaddingException:
            return False

    def guess(self, guess: bytes) -> bool:
        """
        Evaluate the attacker's guess.

        :param guess: The attacker's guess on the hidden message.
        :return: True if the guess is correct.
        """
        print(guess)
        return self._message == guess


class OracleCBCMac(Oracle):

    """
    This oracle represents an online banking web server.

    It holds a secret key,
    used to verify messages from the client.

    It also exposes (for the sake of the challenge)
    an endpoint used by clients to sign a message,
    by using CBC-MAC, the secret key it holds and
    an IV fixed to 0.

    The attacker's goal is to forge a message,
    giving to himself 1M of some given currency.
    """

    def __init__(self):
        super().__init__()
        self._key = matasano.util.random_aes_key()
        self._message = b'from=0_A&tx_list=0_B:10;0_C:1000'

    def challenge(self) -> typing.Tuple[bytes]:
        """
        Return to the caller a plaintext message,
        and its MAC.

        :return: A plaintext message, and its MAC.
        """
        return self._message, matasano.mac.aes_cbc_mac(self._key, self._message, None)

    def experiment(self, message: bytes) -> bytes:
        """
        Allow the caller to sign a message, using CBC-MAC.
        It only works for transaction coming from "Eve".

        :param message: Message to be signed.
        :return: The CBC-MAC of the message.
        """
        assert message.startswith(b'from=0_E')
        return matasano.mac.aes_cbc_mac(self._key, message, iv=None)

    def guess(self, message: bytes, mac: bytes) -> bool:
        """
        Verify the received transaction.
        Return True if `mac` is a valid CBC-MAC for the given `message`.

        :param message: The message to be verified.
        :param mac: A CBC-MAC.
        :return: Whether the message has a valid MAC.
        """
        assert self._message != message
        return matasano.mac.aes_cbc_mac(self._key, message, iv=None) == mac
