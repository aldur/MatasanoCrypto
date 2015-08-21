#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""
The attacker tools will implemented here.
"""

import abc
import time

import matasano.oracle
import matasano.blocks
import matasano.stats
import matasano.prng
import matasano.util


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
        email += matasano.blocks.pkcs(b"admin", 16)
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
    def get_fill_bytes_len(i: int, block_size: int, prefix_len: int=0) -> int:
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
        self.unhidden_string = matasano.blocks.un_pkcs(
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
        self.unhidden_string = matasano.blocks.un_pkcs(
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
                trap = matasano.oracle.random_bytes_range(i)

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
