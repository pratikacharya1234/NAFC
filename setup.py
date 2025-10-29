from setuptools import setup, find_packages
import os

def read_requirements(file):
    with open(file) as f:
        return f.read().splitlines()

# Read requirements
install_requires = read_requirements('requirements.txt')

# Get long description from README
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="nacf",
    version="1.0.0",
    author="Pratika Acharya",
    author_email="pratika.acharya@mail.weber.com",
    description="Neural Authentication Component Framework (NACF)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pratikacharya1234/NAFC",
    packages=find_packages(exclude=["tests", "tests.*"]),
    package_data={
        "nacf": ["py.typed"],
    },
    install_requires=install_requires,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "nacf-cli=nacf.cli.main:main",
        ],
    },
    extras_require={
        "dev": [
            "pytest>=6.2.5",
            "pytest-cov>=2.12.1",
            "pytest-asyncio>=0.15.1",
            "black>=21.7b0",
            "isort>=5.9.3",
            "mypy>=0.910",
            "flake8>=3.9.2",
        ],
        "docs": [
            "sphinx>=4.1.2",
            "sphinx-rtd-theme>=0.5.2",
            "sphinx-autodoc-typehints>=1.12.0",
        ],
        "gpu": [
            "torch>=1.9.0",
            "torchvision>=0.10.0",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/pratikacharya1234/NAF/issues",
        "Source": "https://github.com/pratikacharya1234/NAFC",
    },
    license="Apache License 2.0",
    keywords="eeg authentication neural biometrics security",
)
