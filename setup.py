import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="vault-gcp",
    version="0.0.1",
    author="Kevin Musselman",
    author_email="kevin@kapwing.com",
    description="Authenticate to vault and retrieve env vars",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kapwing/vault-gcp",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
)