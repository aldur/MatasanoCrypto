#!/usr/bin/env/ python
# encoding: utf-8

"""
The attacker tools will implemented here.
"""

import abc
import time
import math
import random

import matasano.oracle
import matasano.blocks
import matasano.stats
import matasano.prng
import matasano.util
import matasano.hash
import matasano.public
import matasano.mac
import matasano.math

__author__ = 'aldur'


class Attacker(object):
    """The generic, abstract, attacker."""
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __init__(self, oracle: matasano.oracle.Oracle):
        self.oracle = oracle

    @abc.abstractmethod
    def attack(self) -> bool:
        """
        Perform the attack against the oracle.
        The default implementation does nothing.

        :return: True if the attack was successful.
        """
        return False


class Eavesdropper(object):
    """The generic, abstract, eavesdropper."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def attack(self) -> bool:
        """
        Perform the eavesdrop attack.
        The default implementation does nothing.

        :return: True if the attack was successful.
        """
        return False


class AttackerProfileForUser(Attacker):
    """
    An admin-user forger.

    :param oracle: An instance of OracleProfileForUser.
    """

    def __init__(self, oracle: matasano.oracle.OracleProfileForUser):
        super().__init__(oracle)

        """
        A block, whose decryption ends perfectly with the last "="
        of the kv string.
        """
        self._base_user = None
        self._role = None

    def get_base_user_profile(self):
        """
        Ask the oracle for a specific profile, such that it is of the form:
        user=...&uid=...&role= || ...
        As you can see, we want the role to be isolated on a single block.

        """
        email_suffix = "@foo.com"
        fixed = sum(
            len(s) for s
            in (
                "email", "uid", "role",  # The keys of the string
                "&", "&", "=", "=", "=",  # The meta characters
                "1",  # The user ID (1-9 is fine)
            )
        )
        email = "a" * (32 - fixed - len(email_suffix)) + email_suffix
        assert len(email) + fixed == 32
        email = email.encode("ascii")
        self._base_user = self.oracle.experiment(email)[0:32]

    def get_role_block(self):
        """
        Ask the oracle for a block of the form:
        ... || admin | padding || ...

        We can provide the oracle only emails.
        Let's build an ad-hoc trap.
        """
        fixed = sum(
            len(s) for s
            in (
                "email",  # The keys of the string
                "=",  # The meta characters
            )
        )
        email = b"a" * (16 - fixed - len(b"@")) + b"@"
        assert len(email) + fixed == 16
        email += matasano.blocks.pkcs_7(b"admin", 16)
        assert len(email) + fixed == 32
        email += b".com"
        self._role = self.oracle.experiment(email)[16:32]

    def attack(self) -> bool:
        """
        Perform the attack.
        Get the base block, add the role, and ask for result to the Oracle.
        """
        assert self._base_user
        assert self._role

        user = self._base_user + self._role
        return self.oracle.guess(user)


class AttackerBitFlippingCBC(Attacker):
    """
    The attacker against the Bit Flipping CBC Oracle.
    Forge a byte buffer such that, once encrypted,
    will be manipulated in order to create a user
    having admin rights (i.e. containing the string
        ";admin=true;"
    )

    We know for sure that the oracle escapes the meta
    characters ";" and "=".
    As a consequence, we won't use them, and we'll
    manipulate the CBC cipher-text.
    """

    def __init__(self, oracle: matasano.oracle.OracleBitflipping):
        super().__init__(oracle)
        self.prefix_len = 32  # The len of the string prefixed

    def attack(self) -> bool:
        """
        Perform the attack against the oracle.
        :return: True if the attack was successful.
        """
        # The prefix string is exactly 32 bytes,
        # so we can simply ignore it

        # We'll use the first block in order to manipulate the next one.
        trap = b"\x00" * 16

        # XOR the meta chars, in order to hide them
        trap += bytes((ord(";") ^ 1,))  # 1-st
        trap += b"admin"
        trap += bytes((ord("=") ^ 1,))  # 7-th
        trap += b"true"

        cipher = bytearray(self.oracle.experiment(trap))
        for i in (0, 6):
            cipher[self.prefix_len + i] ^= 1

        return self.oracle.guess(bytes(cipher))


class AttackerByteAtATimeEcb(Attacker):
    """
    The attacker against the One Byte at a Time Ecb Oracle.
    The oracle holds an unknown string.
    The attacker's goal are:
        - guess the block size of encryption, as used by the oracle (16)
        - guess the AES encryption mode (ECB)
        - discover the unknown fixed string, one byte at a time.
    """

    def __init__(self, oracle: matasano.oracle.OracleByteAtATimeEcb):
        super().__init__(oracle)
        self.block_size = -1
        self.unhidden_string = b""

    @staticmethod
    def get_fill_bytes_len(i: int, block_size: int, prefix_len: int = 0) -> int:
        """
        We want the i-th byte after the input to be the last of a block.
        i.e. i equal to 0 means we want the first byte after the input,
        and that this byte is the last of a block.

        Return the number of bytes to send to the oracle,
        knowing that it will prefix them with prefix_len bytes.

        ... | fill_bytes | ....i || ...

        :param i: The index of the interested byte.
        :param block_size: The block size.
        :param prefix_len: The len of the string prefixed to the attacker's input.
        """
        assert i >= 0
        assert prefix_len >= 0

        fill_bytes_len = \
            block_size - (i % block_size) - 1

        if prefix_len:
            fill_bytes_len -= prefix_len % block_size
            if fill_bytes_len < 0:
                fill_bytes_len %= block_size

        if not fill_bytes_len:
            fill_bytes_len += block_size

        assert 0 < fill_bytes_len <= 16, \
            "Got wrong fill_bytes_len: {}".format(fill_bytes_len)
        return fill_bytes_len

    def attack(self) -> bool:
        """
        Perform the attack against the oracle.
        :return: True if the attack was successful.
        """
        self.discover_block_size()
        is_ecb = self.discover_encryption_mode()

        if not is_ecb:
            # We don't know how to do it!
            return False

        # The len of the hidden string.
        # Excluding padding.
        hidden_string_len = len(
            self.oracle.experiment(b"0" * self.block_size)
        ) - self.block_size

        for i in range(hidden_string_len):
            byte = self.byte_discovery(i)
            self.unhidden_string += byte

        self.unhidden_string = self.unhidden_string.rstrip(b"\x00")
        self.unhidden_string = matasano.blocks.un_pkcs_7(
            self.unhidden_string, self.block_size
        )
        return self.oracle.guess(self.unhidden_string)

    def byte_discovery(self, i: int) -> bytes:
        """
        Attack the oracle in order to know the ith
        byte of the hidden string.

        :param i: byte of interest position
        :return: The ith byte of the hidden string.
        """
        assert self.block_size > 0, \
            "Please discover the block size before calling me!"
        assert 0 <= i <= len(self.unhidden_string), \
            "You're missing the string prefix!"

        """
        The byte we want to discover,
        must be the last of a block.

        We need to submit at least a byte to the oracle.
        Thus we can prepend 1 to block_len bytes of buffer to be encrypted.
        """

        """
        The total number of bytes that we must supply to the oracle,
        for the byte at index i to be last of a block.
        """
        fill_bytes_len = AttackerByteAtATimeEcb.get_fill_bytes_len(
            i, self.block_size
        )

        """
        The bytes that we will be comparing.
        """
        slice_to_ith_block = matasano.blocks.bytes_to_block(
            self.block_size,
            matasano.blocks.ith_byte_block(self.block_size, i + 1)
        )

        """
        The string we will send the oracle while building
        the comparison map.
        """
        trap = b"\x00" * fill_bytes_len + self.unhidden_string
        comparison = {
            self.oracle.experiment(
                trap + c
            )[slice_to_ith_block]: c
            for c in (bytes(chr(c), "ascii") for c in range(0, 128))
            }

        """
        Now we simply remove the already unhidden string from the trap.
        """
        trap = b"\x00" * fill_bytes_len

        cipher = self.oracle.experiment(
            trap
        )[slice_to_ith_block]

        # assert cipher in comparison, \
        #     "Returned cipher is not in previous comparison dictionary. " \
        #     "Something went wrong!"

        # When we get to padding bytes, we can't decrypt anymore.
        return comparison.get(cipher, b"\x00")

    def discover_block_size(self) -> int:
        """
        Discover the block size used by the oracle,
        by feeding it a byte at the time.
        When the size of the cipher will change,
        we'll have found our block size!

        :return: The block size used by the oracle.
        """
        i = 1
        b = b"A" * i
        block_size = len(self.oracle.experiment(b))

        while True:
            i += 1
            b = b"A" * i
            t_block_size = len(self.oracle.experiment(b))

            if block_size != t_block_size:
                self.block_size = t_block_size - block_size
                return self.block_size

    def discover_encryption_mode(self) -> bool:
        """
        Try guessing the encryption mode of the oracle.
        As usual, finding equal blocks means that the encryption
        mode is probably stateless (ECB).

        :return: True if the oracle is using ECB.
        """
        assert self.block_size > 0, \
            "Please discover the block size before calling me!"

        b = b"\x00" * self.block_size * 3
        cipher = self.oracle.experiment(b)
        return matasano.blocks.any_equal_block(cipher)


class AttackerHarderByteAtATimeEcb(AttackerByteAtATimeEcb):
    """
    The attacker against the Harder One Byte at a Time Ecb Oracle.
    The oracle holds an unknown string.
    The attacker's goal are:
        - guess the block size of encryption, as used by the oracle (16)
        - guess the AES encryption mode (ECB)
        - discover the unknown fixed string, one byte at a time.
    It's harder respect to One Byte at a Time because the oracle,
    before encrypting, prefix the attacker's input with a Random,
    static string.
    """

    def __init__(self, oracle: matasano.oracle.OracleHarderByteAtATimeEcb):
        super().__init__(oracle)
        self.prefix_len = -1

    def discover_fixed_string_len(self) -> int:
        """
        Discover the length of the fixed string prefix.
        First of all, discover the last block containing the prefix.
        How? Let the oracle encrypt to single bytes.
        The first block in which the encryption differ is the
        last one of the prefix.
        As a special case, the prefix length could be a multiple of the
        block size. We'll handle this case later.

        Now, we know the last block size.
        Start letting the oracle encrypt a growing number of bytes:
            0, 00, 000, 0000, 00000
        Confront the result.
        When we found that the current result for the last block,
        is equal to the previous one, we've found the length.

        ... || prefix | 0000 || ... == ... || prefix | 0000 || 0..

        :return: The length of the fixed string prefix.
        """
        assert self.block_size > 0, \
            "Please discover the block size before calling me!"

        a = self.oracle.experiment(b"a")
        b = self.oracle.experiment(b"b")

        last_prefix_block = -1  # The prefix string lies in those blocks
        block_slice = None

        assert len(a) == len(b)
        for i in range(0, len(a) // self.block_size):
            block_slice = matasano.blocks.bytes_in_block(self.block_size, i)
            if a[block_slice] != b[block_slice]:
                last_prefix_block = i
                break
        assert last_prefix_block != -1, \
            "Something went wrong while finding the last prefix block."

        previous = a
        for i in range(2, self.block_size + 1):
            new = self.oracle.experiment(b"a" * i)
            if previous[block_slice] == new[block_slice]:
                prefix_len = self.block_size - i + 1
                break
            else:
                previous = new
        else:
            prefix_len = 0
        prefix_len += self.block_size * last_prefix_block

        self.prefix_len = prefix_len
        return prefix_len

    def byte_discovery(self, i: int) -> bytes:
        """
        Attack the oracle in order to know the ith
        byte of the hidden string.

        :param i: byte of interest position
        :return: The ith byte of the hidden string.
        """
        assert self.block_size > 0, \
            "Please discover the block size before calling me!"
        assert self.prefix_len > 0, \
            "Please discover the prefix len before calling me!"
        assert 0 <= i <= len(self.unhidden_string), \
            "You're missing the string prefix!"

        """
        The byte we want to discover,
        must be the last of a block.

        We need to submit at least a byte to the oracle.
        Thus we can prepend 1 to block_len bytes of buffer to be encrypted.
        """

        """
        The total number of bytes that we must supply to the oracle,
        for the byte at index i to be last of a block.
        """
        fill_bytes_len = AttackerByteAtATimeEcb.get_fill_bytes_len(
            i, self.block_size, self.prefix_len
        )

        """
        The bytes that we will be comparing.
        """
        slice_to_ith_block = matasano.blocks.bytes_to_block(
            self.block_size,
            matasano.blocks.ith_byte_block(
                self.block_size, self.prefix_len + i + 1
            )
        )

        """
        The string we will send the oracle while building
        the comparison map.
        """
        trap = b"\x00" * fill_bytes_len + self.unhidden_string
        comparison = {
            self.oracle.experiment(
                trap + c
            )[slice_to_ith_block]: c
            for c in (bytes(chr(c), "ascii") for c in range(0, 128))
            }

        """
        Now we simply remove the already unhidden string from the trap.
        """
        trap = b"\x00" * fill_bytes_len

        cipher = self.oracle.experiment(
            trap
        )[slice_to_ith_block]

        # assert cipher in comparison, \
        #     "Returned cipher is not in previous comparison dictionary. " \
        #     "Something went wrong!"

        # When we get to padding bytes, we can't decrypt anymore.
        return comparison.get(cipher, b"\x00")

    def attack(self) -> bool:
        """
        Perform the attack against the oracle.
        :return: True if the attack was successful.
        """
        self.discover_block_size()
        is_ecb = self.discover_encryption_mode()

        if not is_ecb:
            # We don't know how to do it!
            return False

        self.discover_fixed_string_len()

        # The len of the hidden string.
        # Excluding padding.
        hidden_string_len = len(
            self.oracle.experiment(b"0" * self.block_size)
        ) - (self.prefix_len % self.block_size) - self.block_size

        for i in range(hidden_string_len):
            byte = self.byte_discovery(i)
            self.unhidden_string += byte

        self.unhidden_string = self.unhidden_string.rstrip(b"\x00")
        self.unhidden_string = matasano.blocks.un_pkcs_7(
            self.unhidden_string,
            self.block_size
        )
        return self.oracle.guess(self.unhidden_string)


class AttackerCBCPadding(Attacker):
    """
    The attacker against the CBC padding oracle.
    The oracle holds an unknown string.
    The attacker's goal is to discover such string.

    The oracle provides a method to check whether
    the plaintext related to a given ciphertext has been
    correctly padded.
    This is a side-channel and we'll use it.
    """

    def __init__(self, oracle: matasano.oracle.OracleCBCPadding):
        super().__init__(oracle)
        self.discovered_string = b""

    def attack(self) -> bool:
        """
        The oracle provides a padding check method.
        An attacker can exploit such method to discover
        the encrypted string, while ignoring the encryption key.

        How?
        For each block of the ciphertext, reveal bytes from last to first.
        To do this, create a custom IV, whose byte of interest is set
        to values from 0 to 255.
        Send the block and the IV to the decryption oracle and check
        if the padding is correct.
        If it is correct, then AES_CBC_D(block) ^ custom IV produces
        a correct padding.
        As a consequence, the byte of interest ^ its position
        (i.e. the padding) ^ the same byte of the previous block reveals
        the original plaintext.
        """
        ciphertext, iv = self.oracle.challenge()

        previous = iv
        for b in range(len(ciphertext) // 16):
            discovered = []  # Store already discovered bytes of the block
            block = ciphertext[
                matasano.blocks.bytes_in_block(
                    16, b
                )
            ]

            for i in reversed(range(16)):
                padding_value = 16 - i
                trap = matasano.util.random_bytes_range(i)

                for j in range(256):
                    _trap = trap + bytes((j,))

                    if padding_value > 1:
                        suffix = bytes((
                            padding_value ^ previous_value
                            for previous_value
                            in discovered
                        ))
                        _trap += suffix

                    assert len(_trap) == 16, \
                        "Got bad _trap len {}".format(len(_trap))

                    if self.oracle.experiment(
                            _trap,
                            block
                    ):
                        discovered.insert(0, j ^ padding_value)
                        break
                else:
                    raise Exception(
                        "Something went wrong while attacking the padding oracle - "
                        "block #{}, byte #{}".format(b, i)
                    )

            assert len(discovered) == 16
            self.discovered_string += bytes((
                previous[i] ^ v for i, v in enumerate(discovered)
            ))

            previous = block

        return self.oracle.guess(self.discovered_string)


class AttackerFixedNonceCTR(Attacker):
    """
    The attacker against the fixed nonce CTR oracle.
    The oracle holds a tuple of unknown strings.
    The attacker's goal is to discover such strings.
    """

    def __init__(self, oracle: matasano.oracle.OracleFixedNonceCTR):
        super().__init__(oracle)
        self.discovered_strings = tuple()

    def attack(self) -> bool:
        """
        Employ text analysis tools to discover the encrypted strings.
        All the strings have been encrypted by using the same key-space.
        So the attack methodology is similar to the one used against
        Vigenere.

        Specifically, split in buckets the oracle's challenge.
        Attack each bucket by guessing its XOR key char.
        Iterate until the result is satisfying (i.e. all chars are ASCII).
        """
        buffers = self.oracle.challenge()
        buffers = [bytearray(b) for b in buffers]

        max_len = len(max(buffers, key=lambda b: len(b)))
        buckets = [
            [
                b[i] if len(b) > i else None  # String len differs
                for b
                in buffers
                ]
            for i in range(max_len)
            ]

        # Guess the key
        key = [
            tuple((
                ord(c) for c in
                matasano.stats.most_likely_xor_chars(
                    bytes([byte for byte in b if byte is not None]),
                    3
                )
            ))
            for b in buckets
            ]
        assert len(key) == len(buckets)

        k_used = {
            k: 0 for k in range(len(key))
            }

        k = 0
        while k < len(key):
            v = key[k]
            new_buffers = buffers[:]

            for buffer in new_buffers:
                if len(buffer) <= k:
                    continue  # Skip completed buffers

                buffer[k] ^= v[k_used[k]]
                if buffer[k] >= 128 and k_used[k] < len(v) - 1:
                    k_used[k] += 1
                    break
            else:
                buffers = new_buffers
                k += 1

        self.discovered_strings = tuple(
            bytes(b) for b in buffers
        )
        return self.oracle.guess(self.discovered_strings)


class AttackerMT19937Seed(Attacker):
    """
    Guess the oracle's seed by brute-force.
    Try the possible combinations of seed/output
    after calling the oracle.

    :param oracle: The oracle to be attacked.
    """

    def __init__(self, oracle: matasano.oracle.OracleMT19937Seed):
        super().__init__(oracle)
        self.discovered_seed = None

    def attack(self) -> bool:
        """
        Guess the oracle's seed.

        :return: The attack result.
        """
        start_time = int(time.time())
        challenge = self.oracle.challenge()
        outputs = {
            matasano.prng.MT19937(seed).extract_number(): seed
            for seed in range(
            start_time + self.oracle.sleep_min,
            start_time + self.oracle.sleep_max + 1
        )
            }

        assert challenge in outputs, \
            "Something went wrong, can't find challenge in outputs."
        self.discovered_seed = outputs[challenge]
        return self.oracle.guess(self.discovered_seed)


class AttackerMT19937Clone(Attacker):
    """
    Clone the MT PRNG hold by the Oracle,
    by inverting the tempering function
    for each of the values output by the oracle,
    and passing the result to a newly created MT clone.

    :param oracle: The oracle to be attacked.
    """

    def __init__(self, oracle: matasano.oracle.OracleMT19937Clone):
        super().__init__(oracle)
        self.next_random_numbers = []

    @staticmethod
    def untemper_one(y: int):
        """
        Reverse the first tempering transformation:
        y = x ^ x >> 11

        :param y: The tempering result.
        :return: The value x that produced y.
        """
        prefix = (y >> 21) & 0x07ff  # The first 11 MSB do not change

        middle = (y >> 10) & 0x07ff
        middle ^= prefix

        suffix = y & 0x03ff
        suffix ^= middle >> 1

        x = 0x00
        x |= prefix << 21
        x |= middle << 10
        x |= suffix

        return x

    @staticmethod
    def untemper_two(y: int):
        """
        Reverse the second tempering transformation:
        y = x ^ x << 7 & 2636928640

        :param y: The tempering result.
        :return: The value x that produced y.
        """
        suffix = y & 0x7f  # Last 7 bits are copied

        middle_one = (y >> 7) & 0x7f
        middle_one ^= ((2636928640 >> 7) & 0x7f) & suffix

        middle_two = (y >> 14) & 0x7f
        middle_two ^= ((2636928640 >> 14) & 0x7f) & middle_one

        middle_three = (y >> 21) & 0x7f
        middle_three ^= ((2636928640 >> 21) & 0x7f) & middle_two

        prefix = (y >> 28) & 0x0f
        prefix ^= ((2636928640 >> 28) & 0x0f) & middle_three

        x = 0x00
        x |= prefix << 28
        x |= middle_three << 21
        x |= middle_two << 14
        x |= middle_one << 7
        x |= suffix

        return x

    @staticmethod
    def untemper_three(y: int):
        """
        Reverse the second-last tempering transformation:
        y = x ^ x << 15 & 4022730752

        :param y: The tempering result.
        :return: The value x that produced y.
        """
        suffix = y & 0x7fff  # Last 15 bits are copied

        middle = (y >> 15) & 0x7fff
        middle ^= ((4022730752 >> 15) & 0x7fff) & suffix

        prefix = middle & 0x03  # MSB bits of 4022730752 are set so & is ignored
        prefix ^= (y >> 30) & 0x03

        x = 0x00
        x |= prefix << 30
        x |= middle << 15
        x |= suffix

        return x

    @staticmethod
    def untemper_four(y: int):
        """
        Reverse the last tempering transformation.
        y = x ^ x >> 18

        :param y: The tempering result.
        :return: The value x that produced y.
        """
        return y ^ (y >> 18)

    @staticmethod
    def untemper(y: int):
        """Invert the tempering function applied to n from the Oracle's PRNG.
        We're interested in finding x, given y.
            temper(x) = y
            untemper(y) = x

        :param y: The tempering result.
        :return: The value x that produced y.
        """
        x = AttackerMT19937Clone.untemper_four(y)
        x = AttackerMT19937Clone.untemper_three(x)
        x = AttackerMT19937Clone.untemper_two(x)
        x = AttackerMT19937Clone.untemper_one(x)

        return x

    def attack(self) -> bool:
        """
        Clone the oracle's PRNG.
        :return: True whether the attacks is successful.
        """
        challenge = self.oracle.challenge()
        challenge = [
            AttackerMT19937Clone.untemper(y)
            for y in challenge
            ]
        mt_prng = matasano.prng.MT19937(0)
        mt_prng.mt = challenge

        self.next_random_numbers = list(
            mt_prng.extract_number()
            for _ in range(10)
        )

        return self.oracle.guess(self.next_random_numbers)


class AttackerMT19937Stream(Attacker):
    """
    Guess the oracle's seed (i.e. the encryption key).

    :param oracle: The oracle to be attacked.
    """

    def __init__(self, oracle: matasano.oracle.OracleMT19937Stream):
        super().__init__(oracle)
        self.key = None

    def attack(self) -> bool:
        """
        Clone the oracle's PRNG.
        :return: True whether the attacks is successful.
        """
        challenge = self.oracle.challenge()

        for seed in range(0, 2 ** 16):
            if (matasano.blocks.mt19937_stream(
                    seed,
                    challenge
            ))[-len(self.oracle.known_plaintext):] == self.oracle.known_plaintext:
                self.key = seed
                break
        else:
            raise Exception("Something went wrong while brute-forcing the seed.")

        return self.oracle.guess(self.key)


class AttackerRandomAccessCTR(Attacker):
    """
    Guess the Oracle's hidden plaintext.

    :param oracle: The oracle to be attacked.
    """

    def __init__(self, oracle: matasano.oracle.OracleRandomAccessCTR):
        super().__init__(oracle)
        self.discovered_plaintext = None

    def attack(self) -> bool:
        """
        Replace the plaintext with 0s.
        Once done, you get the exact key, and can recover the hidden plaintext.
        """
        challenge = self.oracle.challenge()

        key = bytes(
            self.oracle.experiment(i, 0)[i]
            for i in range(len(challenge))
        )

        assert len(key) == len(challenge)
        self.discovered_plaintext = matasano.util.xor(
            challenge,
            key
        )

        return self.oracle.guess(bytes(self.discovered_plaintext))


class AttackerBitFlippingCTR(Attacker):
    """
    The attacker against the Bit Flipping CTR Oracle.
    Forge a byte buffer such that, once encrypted,
    will be manipulated in order to create a user
    having admin rights (i.e. containing the string
        ";admin=true;"
    )

    We know for sure that the oracle escapes the meta
    characters ";" and "=".
    As a consequence, we won't use them, and we'll
    manipulate the CTR cipher-text.
    """

    def __init__(self, oracle: matasano.oracle.OracleBitflipping):
        super().__init__(oracle)
        self.prefix_len = 32

    def attack(self) -> bool:
        """
        Perform the attack against the oracle.
        :return: True if the attack was successful.
        """
        trap = bytearray(b"foo;admin=true")
        indexes = (trap.index(b";"), trap.index(b"="))
        for i in indexes:
            trap[i] ^= 1
        trap = bytes(trap)

        cipher = bytearray(self.oracle.experiment(trap))
        for i in indexes:
            cipher[self.prefix_len + i] ^= 1

        return self.oracle.guess(bytes(cipher))


class AttackerCBCKeyIV(Attacker):
    """
    The oracle is using AES CBC.
    The IV is the same key.
    The attacker's goal is to discover the key.

    :param oracle:
    """

    def __init__(self, oracle: matasano.oracle.OracleCBCKeyIV):
        super().__init__(oracle)

    def attack(self) -> bool:
        """
        Acquire the challenge.
        Tamper it.
        Ask the oracle to decrypt and decode it.
        On error the oracle will raise a proper exception,
        containing the decoded plaintext.
        XORring two blocks of such plaintext will
        reveal the key.
        """
        challenge = bytearray(self.oracle.challenge())

        r = matasano.blocks.bytes_in_block(16, 1)
        for i in range(r.start, r.stop):
            challenge[i] = 0
        r = matasano.blocks.bytes_in_block(16, 2)
        for i in range(r.start, r.stop):
            challenge[i] = challenge[i - 16 * 2]

        try:
            self.oracle.experiment(
                bytes(challenge)
            )
        except matasano.oracle.BadAsciiPlaintextException as e:
            p = e.recovered_plaintext
            first = p[matasano.blocks.bytes_in_block(16, 0)]
            third = p[matasano.blocks.bytes_in_block(16, 2)]

            return self.oracle.guess(
                matasano.util.xor(
                    first,
                    third
                )
            )

        assert False, \
            "Something went wrong while attacking the oracle."


class AttackerKeyedMac(Attacker):
    """
    Attack a MD-based keyed MAC.

    Ask the oracle for the MAC of a message.
    Clone the inner hash function status,
    and glue pad the message.
    Forge a new MAC for any new message whose prefix
    is the previously built string.

    :param oracle: The oracle to be attacked.
    :param hash_function: The hash function used to generate the MAC.
    :param padding_function: The function used to pad the message.
    :param hash_to_state: The function to retrieve the state from the hash digest.
    """

    def __init__(
            self,
            oracle: matasano.oracle.OracleKeyedMac,
            hash_function,
            padding_function,
            hash_to_state
    ):
        super().__init__(oracle)
        self.hash_function = hash_function
        self.padding_function = padding_function
        self.hash_to_state = hash_to_state

        self.forged_message = None
        self.forged_mac = None

    def attack(self) -> bool:
        """
        Attack the oracle by forging a MAc
        for an unseen string.

        :return: True if the attack succeeds.
        """
        message = (
            b"comment1=cooking%20MCs;userdata=foo;"
            b"comment2=%20like%20a%20pound%20of%20bacon"
        )
        trap = b";admin=true"

        challenge = self.oracle.challenge(message)
        state = self.hash_to_state(challenge)

        # Get the padded message and add the trap suffix.
        padded_message = self.padding_function(
            b"0" * self.oracle.key_len + message
        )
        padded_message += trap

        # Remove unknown key.
        self.forged_message = padded_message[self.oracle.key_len:]

        # Forge the MAC.
        self.forged_mac = self.hash_function(
            message=trap,
            state=state,
            fake_byte_len=len(padded_message)
        )

        return self.oracle.guess(
            self.forged_message,
            self.forged_mac
        )


class AttackerSHA1KeyedMac(AttackerKeyedMac):
    """
    Attack a SHA1-keyed-MAC oracle.
    """

    def __init__(self, oracle: matasano.oracle.OracleSHA1KeyedMac):
        super().__init__(
            oracle,
            matasano.hash.SHA1,
            matasano.hash.sha1_pad,
            matasano.util.from_big_endian_unsigned_ints
        )


class AttackerMD4KeyedMac(AttackerKeyedMac):
    """
    Attack a SHA1-keyed-MAC oracle.
    """

    def __init__(self, oracle: matasano.oracle.OracleMD4KeyedMac):
        super().__init__(
            oracle,
            matasano.hash.MD4,
            matasano.hash.md4_pad,
            matasano.util.from_little_endian_unsigned_ints
        )


class AttackerRemoteSHA1HMac(Attacker):
    """
    Exploit the timing of the remote server checks
    to brute-force the oracle's secret key.
    """

    def __init__(self, oracle: matasano.oracle.OracleRemoteSHA1HMac):
        super().__init__(oracle)
        self.forged_mac = None

    def attack(self) -> bool:
        """
        The oracle is up and running.
        We query the remote server and keep
        the byte whose average response time has been worst.
        This code is not perfect, but further improvements
        would be un-meaningful.
        """
        message = b"a"

        self.forged_mac = bytearray(
            len(
                matasano.oracle.OracleRemoteSHA1HMac.mac_function(b"key", message)
            )
        )
        sleep_time = matasano.oracle.OracleRemoteSHA1HMac.sleep_time

        for i, _ in enumerate(self.forged_mac):
            times = dict()

            for b in range(256):
                self.forged_mac[i] = b

                start = time.time()
                self.oracle.experiment(message, self.forged_mac)
                stop = time.time()

                times[b] = stop - start

            times = {
                k: v for k, v in times.items()
                if v >= (i + 1) * sleep_time
                }

            while len(times) > 1:
                _times = dict()

                for b in times.keys():
                    self.forged_mac[i] = b

                    start = time.time()
                    self.oracle.experiment(message, self.forged_mac)
                    stop = time.time()

                    _times[b] = stop - start

                times = {
                    k: v for k, v in _times.items()
                    if v >= (i + 1) * sleep_time
                    }
                time.sleep(5)

            self.forged_mac[i] = list(times.keys())[0]
            time.sleep(5)

        return self.oracle.guess(
            message,
            self.forged_mac
        )


class EavesdropperDH(Eavesdropper, matasano.public.DHEntity):
    """
    MITM attack against an instance of the DH protocol.
    Replace Alice's and Bob's public keys with the default p.
    """

    def __init__(
            self,
            alice: matasano.public.DHEntity,
            bob: matasano.public.DHEntity
    ):
        super(EavesdropperDH, self).__init__()

        self.alice, self.bob = alice, bob
        self.alice_pub, self.bob_pub = None, None

        self.eavesdropped_message = None

    def dh_protocol_respond(self, p: int, g: int, pub_a: int):
        """
        The usual response to the DH protocol.
        Forward this response to Bob,
        after replacing the public key with p.

        :param p: The group modulo.
        :param g: A primitive root of p.
        :param pub_a: Alice's DH public key.
        """
        self.alice_pub = pub_a
        self.bob_pub = self.bob.dh_protocol_respond(p, g, p)
        self._session_key = 0
        return p

    def receive_and_send_back(self, ciphertext: bytes) -> bytes:
        """
        Receive the message from Alice,
        forward it to Bob.

        :param ciphertext: The message from Alice to Bob.
        """
        bob_answer = self.bob.receive_and_send_back(ciphertext)
        self.eavesdropped_message = matasano.public.DHEntity.decipher_received_message(
            matasano.public.DHEntity.session_key_to_16_aes_bytes(self._session_key),
            ciphertext
        )
        return bob_answer

    def attack(self) -> bool:
        """
        Trigger the protocol and perform the MITM attack.
        """
        message = b"MessageInABottle"  # Make sure it's a multiple of 16
        assert len(message) % 16 == 0

        self.alice.dh_protocol(self)
        self.alice.send_and_receive(self, message)

        return self.eavesdropped_message == message


class EavesdropperAckDH(Eavesdropper, matasano.public.DHAckEntity):
    """
    MITM attack against an instance of the DH protocol (with ACK).
    Replace the group parameter g with:
        * 1
        * p
        * p -1
    """

    def __init__(
            self,
            alice: matasano.public.DHAckEntity,
            bob: matasano.public.DHAckEntity,
            g: int = 1
    ):
        super(EavesdropperAckDH, self).__init__()

        self.alice, self.bob = alice, bob
        self.eavesdropped_message = None
        self.malicious_g = g

    def set_group_parameters(self, p: int, g: int):
        """
        Replace the g parameter and forward to Bob.

        :param p: The group modulo.
        :param g: A primitive root of p.
        :return: True.
        """
        self.bob.set_group_parameters(p, self.malicious_g)
        return super().set_group_parameters(p, g)

    def dh_protocol_respond(self, p: int, g: int, pub_a: int):
        """
        The usual response to the DH protocol.
        Forward this response to Bob,
        after replacing the public key with p.

        :param p: The group modulo.
        :param g: A primitive root of p.
        :param pub_a: Alice's DH public key.
        """
        pub_bob = self.bob.dh_protocol_respond(p, self.malicious_g, pub_a)

        if self.malicious_g == 1:
            # Both Public keys are always gonna be equal to 1.
            self._session_key = 1
        elif self.malicious_g == p - 1:
            """
            ((p - 1) ^ (a * b)) mod p
            can produce either 1 or -1.
            It depends on whether a * b is even or not.
            For the same reason,
            if pub_a == p - 1, then priv_a was not even.
            So all we need is to compare the public keys to
            discover the session key.
            """
            self._session_key = p - 1 \
                if pub_bob == p - 1 and pub_a == p - 1 \
                else 1
        elif self.malicious_g == p:
            # Both Public keys are always gonna be equal to 0.
            self._session_key = 0
        else:
            assert False, \
                "Something went wrong while MITMing Alice and Bob, bad G value."

        return pub_bob

    def receive_and_send_back(self, ciphertext: bytes) -> bytes:
        """
        Receive the message from Alice,
        forward it to Bob.

        :param ciphertext: The message from Alice to Bob.
        """
        bob_answer = self.bob.receive_and_send_back(ciphertext)
        self.eavesdropped_message = matasano.public.DHEntity.decipher_received_message(
            matasano.public.DHEntity.session_key_to_16_aes_bytes(self._session_key),
            ciphertext
        )
        return bob_answer

    def attack(self) -> bool:
        """
        Trigger the protocol and perform the MITM attack.
        """
        message = b"MessageInABottle"  # Make sure it's a multiple of 16
        assert len(message) % 16 == 0

        self.alice.dh_protocol(self, matasano.public.dh_nist_p, self.malicious_g)
        self.alice.send_and_receive(self, message)

        return self.eavesdropped_message == message


class EavesdropperSimplifiedSRPServer(
    matasano.public.SimplifiedSRPServer,
    Eavesdropper
):
    """
    Brute-force the client's signature in order to discover its password.
    """

    def __init__(self):
        super(Eavesdropper, self).__init__()
        super(matasano.public.SimplifiedSRPServer, self).__init__(password=bytes())

        self.b = 1
        self.B = self.g
        self.u = 1
        self._salt = matasano.util.bytes_for_int(256)

        self.A = -1
        self.client_signature = None
        self.client_password = None

    def srp_protocol_one(self, A: int) -> tuple:
        """
        Complete the phase one of the protocol, responding to the client.

        :param A: The client's public key.
        """
        self.A = A
        return self._salt, self.B, self.u

    def srp_protocol_two(self, signature: bytes) -> bool:
        """
        Return True.

        :param signature: The client's produced MAC.
        :return: Whether the signature is correct.
        """
        self.client_signature = signature
        return True

    def attack(self) -> bool:
        """
        Offline brute-force the client's password from the HMAC signature.
        """

        for password in matasano.util.get_password_wordlist():
            digest = matasano.hash.SHA256(self._salt + password)
            x = int.from_bytes(digest, 'little')
            v = pow(self.g, x, self.N)
            s = pow(
                self.A * pow(v, self.u, self.N),
                self.b,
                self.N
            )

            self._K = matasano.hash.SHA256(
                matasano.util.bytes_for_int(s)
            )

            if matasano.mac.hmac_sha256(
                    self._K,
                    self._salt
            ) == self.client_signature:
                self.client_password = password
                return True
        else:
            return False


class AttackerRSABroadcast:

    """
    Perform the Coppersmith's attack.
    https://en.wikipedia.org/wiki/Coppersmith%27s_Attack

    All the following ciphertexts are encryption of the same message.
    The public key value is fixed to 3.
    The modulus of each key is different from the others.

    :param ciphertext_one: The first encryption.
    :param pub_one: The first public key.
    :param ciphertext_two: The second encryption.
    :param pub_two: The second public key.
    :param ciphertext_three: The third encryption.
    :param pub_three: The third public key.
    """

    def __init__(
            self,
            ciphertext_one: int,
            pub_one: matasano.public.RSA_Pub,
            ciphertext_two: int,
            pub_two: matasano.public.RSA_Pub,
            ciphertext_three: int,
            pub_three: matasano.public.RSA_Pub,
    ):
        self.c_0, self.n_0 = ciphertext_one, pub_one.n
        self.c_1, self.n_1 = ciphertext_two, pub_two.n
        self.c_2, self.n_2 = ciphertext_three, pub_three.n

    def attack(self) -> bytes:
        """
        Perform the attack and return the discovered secret.
        :return: The discovered secret plaintext.
        """

        m_s_0 = self.n_1 * self.n_2
        m_s_1 = self.n_0 * self.n_2
        m_s_2 = self.n_0 * self.n_1

        n = self.n_0 * self.n_1 * self.n_2

        result = sum([
            self.c_0 * m_s_0 * matasano.math.modinv(m_s_0, self.n_0),
            self.c_1 * m_s_1 * matasano.math.modinv(m_s_1, self.n_1),
            self.c_2 * m_s_2 * matasano.math.modinv(m_s_2, self.n_2),
        ])
        result %= n

        return matasano.util.bytes_for_int(
            int(math.ceil(pow(result, 1 / 3.0)))
        )


class AttackerUnpaddedRSARecovery(Attacker):

    """
    Exploit RSA's homomorphic encryption property
    and trick the oracle into decrypting the secret.

    :param oracle: The oracle to be attacked.
    """

    def __init__(self, oracle: matasano.oracle.OracleUnpaddedRSARecovery):
        super(AttackerUnpaddedRSARecovery, self).__init__(oracle)

    def attack(self) -> bool:
        """
        Multiply the oracle's challenge with a new
        ciphertext (trap), whose plaintext value is known
        (s).
        After the oracle's decryption the resulting
        plaintext will be multiplied by s.

        :return: True if the attack is successful.
        """
        cipher, pub = self.oracle.challenge()

        s = random.randint(1, pub.n - 1)
        inv_s = matasano.math.modinv(s, pub.n)
        trap = (pow(s, pub.e, pub.n) * cipher) % pub.n

        plaintext = self.oracle.experiment(trap)
        plaintext = int.from_bytes(plaintext, byteorder="little")
        plaintext = (plaintext * inv_s) % pub.n

        return self.oracle.guess(
            matasano.util.bytes_for_int(
                plaintext
            )
        )


class AttackerRSAPaddedSignatureVerifier(Attacker):

    """
    Forge a signature by creating a perfect cube,
    that respects the PKCS1.5 padding rules.

    :param oracle: The oracle's to be attacked.
    """

    def __init__(self, oracle: matasano.oracle.OracleRSAPaddedSignatureVerifier):
        super(AttackerRSAPaddedSignatureVerifier, self).__init__(oracle)

    def attack(self) -> bool:
        """
        Find a perfect cube that, when represented in binary form,
        has the prefix matching the expected padding.
        A working signature can be forged by using such cube.
        """
        message, pub = self.oracle.challenge()

        assert pub.e == 3, \
            "Can't attack if Oracle public key is not 3."

        pad_f = matasano.oracle.OracleRSAPaddedSignatureVerifier.pad_function
        hash_f = matasano.oracle.OracleRSAPaddedSignatureVerifier.hash_function
        block_size = matasano.oracle.OracleRSAPaddedSignatureVerifier.block_size
        byteorder = 'big'  # Because we're messing with the suffix

        padded_message = pad_f(
            hash_f(message)
        )

        padded_message += b"\x00" * block_size * 2
        n = int.from_bytes(padded_message, byteorder=byteorder)
        forged_signature = matasano.math.integer_cube_root(n) + 1

        forged_message = pow(forged_signature, 3)
        assert forged_message < pub.n

        forged_message = matasano.util.bytes_for_int(
            forged_message,
            length=len(padded_message),
            byteorder=byteorder
        )

        assert padded_message[:block_size] == forged_message[:block_size]
        return self.oracle.guess(forged_signature)


class AttackerDSAKeyFromNonce(Attacker):

    """
    Recover the DSA private key by brute-forcing the nonce value.
    :param oracle: The oracle to be attacked.
    """

    def __init__(self, oracle: matasano.oracle.OracleDSAKeyFromNonce):
        super(AttackerDSAKeyFromNonce, self).__init__(oracle)
        self.private_key_x = -1

    def attack(self) -> bool:
        """
        Brute-force the nonce value and discover the Oracle's private key.
        """
        oracle_type = type(self.oracle)

        y, p, q, g = oracle_type.public_key
        r, s = oracle_type.signature

        r_inv = matasano.math.modinv(r, q)
        digest = oracle_type.hash_to_int(
            oracle_type.hash_function(oracle_type.message)
        )

        for k in oracle_type.k_range:
            x = (((s * k) - digest) * r_inv) % q
            if pow(g, x, p) == y:
                break
        else:
            assert False, \
                "Something went wrong while brute-forcing the nonce."

        self.private_key_x = x
        return self.oracle.guess(self.private_key_x)
