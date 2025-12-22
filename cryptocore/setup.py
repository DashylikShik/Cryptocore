from setuptools import setup, find_packages

setup(
    name="cryptocore",
    version="1.0.0",
    packages=['src', 'src.hash', 'src.kdf', 'src.mac', 'src.modes'],
    package_dir={
        'src': 'src',
        'src.hash': 'src/hash',
        'src.kdf': 'src/kdf', 
        'src.mac': 'src/mac',
        'src.modes': 'src/modes',
    },
    install_requires=["pycryptodome>=3.19.0"],
    entry_points={
        "console_scripts": [
            "cryptocore = src.main:main",
        ],
    },
    python_requires=">=3.7",
)