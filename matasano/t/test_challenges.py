#!/usr/bin/env/ python
# encoding: utf-8

"""
Test each challenge.
"""

import unittest
import inspect
import functools

import matasano.challenges

__author__ = 'aldur'


class ChallengeTestCase(unittest.TestCase):

    def challenge(self, challenge_f):
        """
        Test the challenge, asserting it doesn't fail.

        :param challenge_f: The challenge to be tested.
        """
        result = challenge_f()

        if result is not None:
            self.assertTrue(result)


"""
Automatically add test methods from each challenge.
"""
excluded = {"challenge", "main"}  # manually exclude some functions.
# exclude slow tests by default
slows = {
    "twentytwo", "twentyfour", "twenty",
    "thirtyeight", "thirtytwo", "thirtyone",
    "fortyseven", "fortyeight",
}
for f_name, f in inspect.getmembers(matasano.challenges, inspect.isfunction):
    if not f_name.startswith("_") and f_name not in excluded:
        test_challenge = functools.partialmethod(ChallengeTestCase.challenge, challenge_f=f)
        if f_name in slows:
            test_challenge = unittest.skip("Slow test")
        setattr(
            ChallengeTestCase,
            "test_{}".format(f_name),
            test_challenge
        )

if __name__ == '__main__':
    unittest.main()
