from setuptools import setup, find_packages

setup(
    name="formal_pledge",
    version="0.1.0",
    description="Detect remote LIBC version with format string vuln",
    author="k4lizen",
    packages=['formal_pledge'],
    install_requires=['pwntools']
)