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

    def attack(self) -> bool:
        """
        Perform the attack against the oracle.
        :return: True if the attack was successful.
        """
        self.block_size = self.discover_block_size()
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
        self.unhidden_string = self.unhidden_string[0:-1]
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
        must be places as the last of a block.

        We need to submit at least a byte to the oracle.
        Thus we can prepend 1 to 16 bytes of buffer to be encrypted.
        """

        trap_bytes = b"\x00" * (self.block_size - ((i + 1) % self.block_size))
        comparison = {
            self.oracle.experiment(
                trap_bytes + self.unhidden_string + c
            )[0:self.block_size * (((i + 1) // self.block_size) + 1)]: c
            for c in (bytes(chr(c), "ascii") for c in range(0, 128))
        }
        cipher = self.oracle.experiment(
            trap_bytes
        )[0:self.block_size * (((i + 1) // self.block_size) + 1)]

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
                return t_block_size - block_size

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
