#!/usr/bin/env python
# encoding: utf-8

from setuptools import setup

setup(
    name='MatasanoCrypto',
    description='A set of tools to use for the Matasano Crypto Challenge.',
    version='0.1',

    url='https://github.com/aldur/MatasanoCrypto',
    license='MIT',

    author='aldur',
    author_email='adrianodl@hotmail.it',

    packages=['matasano'],
    install_requires=[
        'pycrypto',
        'colorama'
    ],

    scripts=['bin/matasano'],

    zip_safe=False,
    include_package_data=True,
)
