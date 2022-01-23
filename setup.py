"""
nmap_home packaging and deployment
More details: https://setuptools.pypa.io/en/latest/userguide/quickstart.html
"""
import os

import setuptools
from setuptools import setup
from home_nmap import __version__


def __read__(file_name):
    return open(os.path.join(os.path.dirname(__file__), file_name)).read()


setup(
    name="home_nmap",
    version=__version__,
    author="Jose Vicente Nunez Zuleta",
    long_description_content_type="text/markdown",
    long_description=__read__('tutorial/README.md'),
    author_email="kodegeek.com@protonmail.com",
    description=__doc__,
    license="Apache",
    keywords="nmap query",
    url="https://github.com/josevnz/homenmap",
    packages=setuptools.find_packages(),
    # https://pypi.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "Environment :: X11 Applications",
        "Intended Audience :: System Administrators"
        "License :: OSI Approved :: Apache Software License"
    ],
    setup_requires=[
        "setuptools>=60.2.0",
        "wheel>=0.37.1",
        "build>=0.7.0"
    ],
    install_requires=[
        "rich>=9.5.1",
        "dearpygui>=1.1",
        "python-nmap>=0.7.1",
        "diagrams>=0.20.0",
        "uvicorn[standard]>=0.17.0",
        "lxml==4.7.1",
        "requests>=2.27.1",
        "cpe==1.2.1",
        "pydantic==1.9.0",
        "fastapi_simple_security>=1.0.0",
        "fastapi>=0.70",
    ],
    scripts=[
        "scripts/home_scan.py",
        "scripts/nmap_scan_rpt.py",
        "scripts/generate_diagrams.py"
    ],
    python_requires=">=3.9",
)
