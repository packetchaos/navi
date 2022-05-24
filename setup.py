from setuptools import setup, find_packages
from os import path


this_directory = path.abspath(path.dirname(__file__))

with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='navi pro',
    version='6.9.0',
    description="A command-line interface to Tenable.io",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author="Casey Reid",
    author_email="itprofguru@gmail.com",
    url="https://github.com/packetchaos/Navi",
    license="GNUv3",
    keywords='tenable tenable_io navi tio, lumin, navi pro, tio cli, tenable io cli, automation',
    packages=find_packages(exclude=['docs', 'tests']),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'Click>=7.0',
        'requests>=2.26.0',
        'flask>=1.1.1',
        'IPy>=1.0',
        'pytenable>=1.4.3',
        'arrow>=0.17.0',
        'boto3>=1.17.48',
        'pexpect>=4.8.0',
        'typing-extensions>=4.0.1'
    ],
    python_requires='>=3.0',
    extras_require={
    },
    entry_points={
        'console_scripts': [
            'navi=navi.cli:cli',
        ],
    },
)

