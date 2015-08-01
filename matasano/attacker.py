#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""
The attacker tools will implemented here.
"""

import abc
import matasano.oracle
import matasano.blocks


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
        self.unhidden_string = matasano.blocks.un_pkcs(self.unhidden_string)
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
            block_slice = matasano.blocks.bytes_in_blocks(self.block_size, i)
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
        self.unhidden_string = matasano.blocks.un_pkcs(self.unhidden_string)
        return self.oracle.guess(self.unhidden_string)
