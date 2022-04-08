from setuptools import find_packages, setup
from pathlib import Path

project_directory = Path(__file__).parent.resolve()

setup(
    name="purehash",
    version="1.1.0",
    description="Pure Python implementations of common hashing algorithms.",
    long_description=(project_directory / "README.md").read_text("utf-8"),
    long_description_content_type="text/markdown",
    url="https://github.com/oshawk/purehash",
    author="Oshawk",
    classifiers=[
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3 :: Only",
    ],
    keywords="hash, cryptography",
    packages=find_packages(),
    python_requires=">=3.7, <4",
    extras_require={
        "dev": ["pre-commit", "black", "mypy", "twine"],
        "test": ["pytest"],
    },
)
