# -*- coding: utf-8 -*-
from setuptools import find_packages
from setuptools import setup

setup(
    name='guillotina_declperm',
    description='A declarative permissions system for guillotina',
    version=open('VERSION').read().strip(),
    long_description=(
        open('README.rst').read() + '\n' + open('CHANGELOG.rst').read()),
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    author='Christophe de Vienne',
    author_email='christophe.devienne@orus.io',
    keywords='async guillotina acl',
    url='https://pypi.python.org/pypi/guillotina_declperm',
    license='GPL version 3',
    setup_requires=[
        'pytest-runner',
    ],
    zip_safe=True,
    include_package_data=True,
    packages=find_packages(exclude=['ez_setup']),
    install_requires=[
        'setuptools',
        'guillotina>=2.5.0.dev0',
    ],
    tests_require=[
        'pytest',
    ])
