# dissect.util

A Dissect module implementing various utility functions for the other Dissect modules. For more information, please see
[the documentation](https://docs.dissect.tools/en/latest/projects/dissect.util/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.util` is available on [PyPI](https://pypi.org/project/dissect.util/).

```bash
pip install dissect.util
```

`dissect.util` includes both a pure Python implementation as well as a faster native Rust implementation of the LZ4 and LZO decompression algorithms.
Pre-build wheels are available for most common platforms and the native implementation will automatically be used.
In the rare case that a pre-build wheel is not available, the pure Python implementation will automatically be used instead.
If you wish to build your own wheel in the case a pre-build one is not available for your platform, you can do so by running the following command:

```bash
tox -e build-native
```

Note that you'll need to bring your own Rust toolchain for the target platform you wish to build a wheel for. For example, using [rustup](https://rustup.rs).

## Build and test instructions

This project uses `tox` to build source and wheel distributions. Run the following command from the root folder to build
these:

```bash
tox -e build
```

The build artifacts can be found in the `dist/` directory.

`tox` is also used to run linting and unit tests in a self-contained environment. To run both linting and unit tests
using the default installed Python version, run:

```bash
tox
```

For a more elaborate explanation on how to build and test the project, please see [the
documentation](https://docs.dissect.tools/en/latest/contributing/tooling.html).

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

Dissect is released as open source by Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc
(<https://www.nccgroup.com>).

Developed by the Dissect Team (<dissect@fox-it.com>) and made available at <https://github.com/fox-it/dissect>.

License terms: Apache License 2.0 (<https://www.apache.org/licenses/LICENSE-2.0>). For more information, see the LICENSE file.
