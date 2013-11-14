# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='plinth',
    version='0.0.1',
    description='Python Library for InterNetworking with TeleHash',
    long_description=readme,
    author='David Van Duzer',
    author_email='dvd@tennica.net',
    url='https://github.com/dvanduzer/plinth',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)

