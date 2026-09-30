from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ns-bos",
    version="0.1.0",
    author="Bison Venture Partners LLC dba NGARI",
    author_email="support@ngari.xyz",
    description="NGARi Sovereign Business Operating System - Open Source Kernel",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/NGARiAI/ns-bos-kernel",
    project_urls={
        "Bug Tracker": "https://github.com/NGARiAI/ns-bos-kernel/issues",
        "Documentation": "https://ngari.xyz/docs",
        "Source Code": "https://github.com/NGARiAI/ns-bos-kernel",
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: System :: Distributed Computing",
    ],
    package_dir={"": "."},
    packages=find_packages(where="."),
    python_requires=">=3.9",
    install_requires=[
        "cryptography==50.0.0",
        "requests==2.34.2",
        "pyyaml==6.0.3",
        "beautifulsoup4==4.15.0",
    ],
    entry_points={
        "console_scripts": [
            "ns-bos=core.kernel:main",
        ],
    },
)
