from setuptools import setup, find_packages

setup(
    packages=find_packages(
        include=["strilight*"],
        exclude=[
            "strilight.tests*",
            "strilight.arch*",
            "strilight.extensions*",
        ],
    ),
    package_data={"strilight": ["py.typed"]},
)
