from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ns-bos",
    version="0.1.0",
    author="NGARI Corporation",
    author_email="contact@ngari.com",
    description="NGARI Sovereign Business Operating System - Open Source Kernel",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ngariglobal/ns-bos",
    project_urls={
        "Bug Tracker": "https://github.com/ngariglobal/ns-bos/issues",
        "Documentation": "https://ngari.com/docs",
        "Source Code": "https://github.com/ngariglobal/ns-bos",
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: System :: Distributed Computing",
    ],
    package_dir={"": "."},
    packages=find_packages(where="."),
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "requests>=2.31.0",
        "pyyaml>=6.0",
        "beautifulsoup4>=4.12.0",
    ],
    entry_points={
        "console_scripts": [
            "ns-bos=core.kernel:main",
        ],
    },
)
