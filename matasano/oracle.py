#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""
The oracle related stuff.
Random generations, games, and so on.
"""

import random
import base64
import abc
import re
import collections
import time

import matasano.blocks
import matasano.util
import matasano.prng
import matasano.mac


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
        key = random_aes_key()

        # Add some randomness
        b = random_bytes_random_range(5, 10) + b + random_bytes_random_range(5, 10)
        # Pad if necessary
        b = matasano.blocks.pkcs(b, 16)

        ciphertext = self.cipher(key, b)
        if isinstance(ciphertext, collections.Sequence):
            return ciphertext[0]
        else:
            return ciphertext

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
        self._key = random_aes_key()
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
            matasano.blocks.pkcs(profile.encode("ascii"), 16)
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
        self._consistent_key = random_aes_key()

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
            input_string = matasano.blocks.pkcs(input_string, 16)

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
        self._consistent_key = random_aes_key()
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
        self._prefix = random_bytes_random_range(1, 32)

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


def random_bytes_random_range(low: int, high: int) -> bytes:
    """
    Generate low to high random bytes.

    :param low: The minimum number of bytes to generate.
    :param high: The maximum (inclusive) number of bytes to generate.
    :return: A random range of random bytes s.t. low <= len(output) <= max.
    """
    return bytes(
        random.randint(0, 255)
        for _
        in range(0, random.randint(low, high))
    )


def random_bytes_range(length: int) -> bytes:
    """
    Generate a sequence of specified length of random bytes.

    :param length: The len of the range.
    :return: A new range of random bytes.
    """
    return bytes(
        random.randint(0, 255)
        for _
        in range(0, length)
    )


def random_aes_key() -> bytes:
    """Generate a random AES key (16 bytes)

    :return: 16 bytes.
    """
    return random_bytes_range(16)


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
        self._consistent_key = random_aes_key()

        with open(strings_path, "rb") as strings:
            s = random.choice(strings.readlines()).rstrip()
            self._hidden_string = matasano.blocks.pkcs(s, 16)

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
            matasano.blocks.un_pkcs(plaintext, 16)
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
        self._consistent_key = random_aes_key()

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
            random_bytes_random_range(
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

        self._consistent_key = random_aes_key()
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
        self._consistent_key = random_aes_key()

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
        self._secret_key = random_aes_key()
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
