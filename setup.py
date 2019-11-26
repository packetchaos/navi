from setuptools import setup, find_packages

setup(
    name='navi',
    version="5.0.0",
    description="A command-line interface to Tenable.io",
    author="Casey Reid",
    author_email="itprofguru@gmail.com",
    url="https://github.com/packetchaos/Navi",
    license="GNUv3",
    keywords='tenable tenable_io navi tio, lumin',
    packages=find_packages(exclude=['docs', 'tests']),
    install_requires=[
        'Click>=7.0',
        'requests',
        'pprint>=0.1'
    ],
    python_requires='>=3.7',
    extras_require={
    },
    entry_points={
        'console_scripts': [
            'Navi=Navi.cli:cli',
        ],
    },
)

