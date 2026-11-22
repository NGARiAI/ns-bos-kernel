from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ns-bos",
    version="0.2.0",
    author="Bison Venture Partners LLC dba NGARI",
    author_email="support@ngari.ai",
    description="NGARi Sovereign Business Operating System - Open Source Kernel",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/NGARiAI/ns-bos-kernel",
    project_urls={
        "Bug Tracker": "https://github.com/NGARiAI/ns-bos-kernel/issues",
        "Documentation": "https://ngari.ai/kernel",
        "Source Code": "https://github.com/NGARiAI/ns-bos-kernel",
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: System :: Distributed Computing",
    ],
    # The `core.kernel` namespace is packaged from the repository root, two levels
    # up. Packages are listed explicitly, not discovered with find_*: this directory
    # is the build root, so discovery would also pick up a `build/` directory left
    # by an earlier install and ship it as `core.kernel.build.lib.*`.
    package_dir={"": "../.."},
    packages=[
        "core",
        "core.kernel",
        "core.kernel.agent_runtime",
        "core.kernel.data_plane",
        "core.kernel.generative_ui",
        "core.kernel.hal",
        "core.kernel.inference",
        "core.kernel.network_sync",
        "core.kernel.sandbox",
    ],
    python_requires=">=3.10",
    install_requires=[
        "cryptography==50.0.0",
        "requests==2.34.2",
        "pyyaml==6.0.3",
    ],
    entry_points={
        "console_scripts": [
            "ns-bos=core.kernel:main",
        ],
    },
)
