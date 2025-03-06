# SCITT CCF Ledger Functional Tests

This repository contains functional tests for the SCITT CCF Ledger.

The functional tests are written in Python and interact with a running service.
The majority of tests in this directory are focused on testing the behaviour of
the service, but to a lesser extent, we also write tests that exercise the
behaviour of the pyscitt package and `scitt` CLI.

## Structure

This directory contains many `test_foo.py` files, which contain a set of tests.
There is no strict delimitation between the different files, and where a new
test needs to be added is generally a matter of best judgment.

Inside the test files, each individual test is written as a `test_foo`
function. Optionally, many related tests can be grouped together in a `TestBar`
class, which allows helper functions and fixtures to be shared while keeping
the overall file tidy. In general and where possible, prefer writing multiple
smaller tests, each interacting with a feature of the service differently, than
one large test function.

## Pytest Fixtures

The tests are written using the pytest framework, and makes extensive use of
its fixtures mechanism. Fixtures setup the environment the tests run in and
provide helper utilities to interact with it. For a more thorough overview of
pytest fixtures, please refer to [the pytest documentation](https://docs.pytest.org/en/7.2.x/explanation/fixtures.html).

To use a fixture, a test function needs a parameter representing the fixture.
For example, a test which needs access to a `Client` instance to interact with
the service would have a `client` parameter, which is can use inside the test
body.

```python
def test_parameters(client: Client):
  assert client.get_parameters()["treeAlgorithm"] == "CCF"
```

The name of this parameter must match of the name of the fixtures. See below
for a list of the most essential fixtures. The `Client` type annotation is
optional.

### Fixture factories and helper functions

Throughout the execution of a test function, there can only ever be a single
instance of a given fixture. For certain kinds of resources, this may be
appropriate, such as the client fixture above. For others, we may want to
create many instances of a resource. In these cases, the fixture acts as a
factory, which can be called repeatedly to create each instance of the
resource.

Some fixtures are in fact helper functions which may not return any
value, but have a side effect each time they are called. For example, in the
`test_cli.py` file, the `run` fixture is used to execute the `scitt` CLI:

```python
def test_constitution(run, tmp_path):
  run("governance", "constitution", f"--output={tmp_path}/constitution.js")
```

The example above also shows how multiple fixtures can be combined in a single
test, here both the `run` helper and [the built-in pytest `tmp_path` fixture](https://docs.pytest.org/en/7.2.x/how-to/tmp_path.html).

## Ledger service

The test infrastructure manages the environment the tests run in, and provides
fixtures to interact with it. In particular, this includes providing a ledger
service instance. The test infrastructure can operate in two modes, depending
on whether the `--start-cchost` flag was provided to pytest.

If the flag is provided, the infrastructure will start, configure and stop one
or more ledger services as necessary. This is generally more convenient and
ensures the tests are running against a known clean state.

Otherwise, the infrastructure can use an external ledger service. The service
must already be running and open for traffic before the tests are run. This
can be used to run against a SCITT ledger running inside a Docker container for
example. Note that member access is required, and running the tests will
disrupt the service. It must not be used against a production instance.

Most individual test functions are agnostic of how and where the service is
running, and are written in a generic fashion allowing them to run under either
mode.

## Test markers

Tests may be annotated either to change the behaviour of the test
infrastructure, or to skip the test when certain conditions aren't met.
Annotations are added using a `@pytest.mark.foo` decorator on the particular
test function or class.

The `isolated_test` marker will instruct the test infrastructure to use a
dedicated ledger instance, shared among all tests in the class. If applied on a
test function that is not part of a class, then the ledger instance is used for
this test function only. This is useful for tests that are considered risky,
and have a high chance of leaving the service in an unusable state (which would
make all subsequent tests fail), or when the test requires an empty ledger to
start with. Tests marked with `isolated_test` are skipped if an external service
is used.


## Using the existing fixtures

This is a non-exhaustive summary of the most useful SCITT-specific fixtures
included in the test infrastructure.

The `client` fixture gives access to a `Client` object that is pre-configured
to communicate with the local SCITT ledger service. Depending on the test
markers and how pytest was invoked, this may be an external service, a managed
service that is shared among all tests, or an isolated service that was started
just for a particular test class. The `Client` instance is configured with a
member private key, enabling governance operations, but no authentication
token. A token can be provided by calling `client.replace(auth_token=...)`.

The `service_url` and `member_auth` fixtures give access to the details
necessary to interact with the running SCITT service. Generally, these fixtures
do not need to be used, as the aforementioned `client` fixture provides a more
practical way to use the service. The `member_auth_path` fixture provides the
same credentials as `member_auth`, but as files on disk rather than in-memory
strings.

The `configure_service` fixture is a function that can be called to modify the
service's SCITT configuration. This can be used to configure authentication,
policies, etc. If no authentication setting is specified, the service is left
open to all (this differs from the usual ledger's default which is to reject
all incoming requests).

The `cert_authority` fixture can be used to create
new X509-based identities. The fixture creates a new Certificate Authority and
the service is configured to trust its root certificate. New identities are
created by calling `cert_authority.create_identity()`.

The `cchost` fixture gives direct access to the underlying `CCHost` instance
that is managing the service. This fixture is only available if pytest was
configured to start its own cchost instances. If a test requires this fixture,
it should therefore be annotated with `@pytest.mark.isolated_test`. It is rare
to need to interact directly with the running process and use this fixture.
Most of the time, the `client` fixture is sufficient.

As mentioned earlier, the `test_cli.py` file features a `run` fixture function.
This function can be used to execute the `scitt` CLI. If the `with_service_url`
or `with_member_auth` keyword arguments are true, appropriate flags are added
to the command invocation in order for the tooling to be able to contact the
service. This fixture cannot be used in other files, where direct interaction
with the service using the pyscitt programmatic API is preferred.

## Defining new fixtures

Before defining a new fixture, one should consider whether the same
functionality could instead be provided as a standard class or function
definition. In general, a fixture may be preferred and/or necessary in these
circustamces:
- Set-up is verbose, in a way that cannot be hidden away as a function
- Instances are long-lived and benefit from pytest's long scopes
- The functionality depends on another existing fixture

Fixtures can be defined in multiple places, depending on how generic they are.
The most general fixtures, that will be used across multiple test files, should
be defined in the `infra/fixtures.py` file. More specific fixtures, that relate
to just one area of the service can be defined in individual test files.
Finally, if a fixture is only relevant to a couple of tests, the tests can be
grouped in a class and the fixture defined as a method in that class.

Where it makes sense, it is better to implement the fixture's functionality
with a general-purpose interface that is not tied to pytest, allowing it to be
re-used in other contexts. The fixture definition becomes a thin wrapper to
instantiate this generic interface. For example the `client` and `cchost`
fixtures are wrappers around the re-usable `Client` and `CCHost`.

Each fixture is associated with a scope, which can be one of `function` (the
default), `class`, `module`, `package` or `session`. Fixtures are only
instantiated once per their scope, and the value is reused throughout all tests
of that scope. In general, longer scopes create more interference between tests
and result in a more fragile test suite. On the other hand, longer scopes can
reduce total test time by amortizing expensive initialization costs across
multiple tests.

