#!/usr/bin/env python3
from setuptools import setup, find_packages


setup(
    name='mystik',
    version='1.0.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'mystik = mystik:main'
        ]
    },
    install_requires=[
        'regex==2023.8.8'
    ],
    include_package_data=True,
    author='Dennis Carlson',
    author_email='dcarlson@gotham-security.com',
    description='A Python-based, Rust-core secret searching tool ',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/GoVanguard/Mystik',
    license='MIT',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3'
    ],
)
