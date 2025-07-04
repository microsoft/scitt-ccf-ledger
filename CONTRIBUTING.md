# Contributing

This project welcomes contributions and suggestions. Most contributions require you to
agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the
instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Contributor Guide
Please remember to update the [CHANGELOG](CHANGELOG.md) and add appropriate tests.

### Adding a unit test

To add a unit test for a function `new_function()` in `app/src/foo/bar.h`:
  - Create the file `app/unit-tests/foo/bar_test.cpp` if it doesn't exist and add it to `app/CMakeLists.txt` in the unit_tests' `add_executable` e.g.:
        ```
        add_executable(
          unit_tests
          <files...>
          <...>
    ->    unit-tests/foo/bar_test.cpp
        )
        ```
  - In `app/unit-tests/foo/bar_test.cpp` create TEST()s using the [GoogleTest framework](https://google.github.io/googletest/).
  - The test will be run as part of the virtual platform build:
      ```
      PLATFORM=virtual ./build.sh
      ```

### Adding a functional test

Most likely you can extend an existing `test/test_*.py` test. Otherwise create a new test file matching `test/test_*.py` and it will be run by `./run_functional_tests.sh` against a CCF network with the scitt-ccf-ledger app which exists for the duration of all of the functional tests.

### Code formatting

Parts of the codebase have formatting rules enforced by the CI pipeline. The rules can be checked locally by running [`scripts/ci-checks.sh`](scripts/ci-checks.sh). Formatting can be fixed automatically by running `scripts/ci-checks.sh -f`.
