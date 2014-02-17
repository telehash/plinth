# -*- coding: utf-8 -*-

from setuptools import setup


with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

packages = [
    'plinth'
]

requires = [
    'PyTomCrypt >= 0.9.0',
    'gevent >= 1.0'
]

setup(
    name='plinth',
    version='0.0.14',
    description='Python Library for InterNetworking with TeleHash',
    long_description=readme,
    author='David Van Duzer',
    author_email='dvd@tennica.net',
    url='https://github.com/telehash/plinth',
    license=license,
    packages=packages,
    package_data = {'': ['LICENSE']},
    package_dir = {'plinth': 'plinth'},
    include_package_data=True,
    install_requires=requires,
    classifiers=(
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
    ),
)
