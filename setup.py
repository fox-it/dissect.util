from setuptools import find_packages, setup

setup(
    name="dissect.util",
    packages=list(map(lambda v: "dissect." + v, find_packages("dissect"))),
    entry_points={
        "console_scripts": [
            "dump-nskeyedarchiver=dissect.util.tools.dump_nskeyedarchiver:main",
        ],
    },
)
