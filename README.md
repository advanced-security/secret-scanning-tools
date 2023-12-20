# Secret Scanning Tools

> ℹ️ This is an _unofficial_ tool created by Field Security Services, and is not officially supported by GitHub.

This is a testing suite for GitHub Secret Scanning Custom Patterns.

It can be used in combination with GitHub Actions to test custom patterns before they are deployed.

An example repository that uses this Action is [advanced-security/secret-scanning-custom-patterns](https://github.com/advanced-security/secret-scanning-custom-patterns).

A sample custom patterns config file compatible with this tool suite is provided in [`examples/config/patterns.yml`](examples/config/patterns.yml).

## Usage in Actions

```yaml
- name: Secret Scanning Test Suite
  uses: advanced-security/secret-scanning-tools@v1
```

### Advanced Configuration

```yaml
- name: Secret Scanning Test Suite
  uses: advanced-security/secret-scanning-tools@v1
  with:
    # Modes to run
    # > 'validate' (default), 'all', 'snapshot', 'markdown'
    mode: 'validate'
```

### Using GitHub App Token

```yaml
- name: Get Token
  id: get_workflow_token
  uses: peter-murray/workflow-application-token-action@v1
  with:
    application_id: ${{ secrets.ADVANCED_SECURITY_APP_ID }}
    application_private_key: ${{ secrets.ADVANCED_SECURITY_APP_KEY }}

- name: Secret Scanning Test Suite
  uses: advanced-security/secret-scanning-tools@v1
  with:
    token: ${{ steps.get_workflow_token.outputs.token }}
```

### Defining expected results for online testing

You can put a CSV file named `<pattern_id>.csv` in directory named `__snapshots__` in the same directory as the `pattern.yml` file.

The CSV file should use the format shown in this example:

```csv
secret_type,secret_type_display_name,commit,path,start_line,end_line,start_column,end_column
"any_ipv4_addresses","Any IPv4 Addresses","403f06e166941f11d11e79201ee3ed0df9dbb9bb011843899c4b6dd62693b27d","configs/pom.xml","42","42","22","30",
"any_ipv4_addresses","Any IPv4 Addresses","c77e473ca7d07f7addbaf0eb5e2a1c4ca664a2f832c38771d06fee5793704a64","uri/ipaddresses/ipv4_random.txt","11","11","18","30",
"any_ipv4_addresses","Any IPv4 Addresses","c77e473ca7d07f7addbaf0eb5e2a1c4ca664a2f832c38771d06fee5793704a64","uri/ipv4_random.txt","11","11","18","30",
"any_ipv4_addresses","Any IPv4 Addresses","a2c5576efda66704b0f03d6241a5a5539e7f9331b883ea5177ccbf98aca615ac","uri/ipv4.txt","1","1","1","8",
"any_ipv4_addresses","Any IPv4 Addresses","f5047344122f0dee9974ba6761e61c6b8649e1f3968d13a635ebbf7be53a3a0d","uri/ipaddresses/ipv4_private.txt","8","8","1","9",
"any_ipv4_addresses","Any IPv4 Addresses","f5047344122f0dee9974ba6761e61c6b8649e1f3968d13a635ebbf7be53a3a0d","uri/ipv4_private.txt","8","8","1","9",
"any_ipv4_addresses","Any IPv4 Addresses","37d7a80604871e579850a658c7add2ae7557d0c6abcc9b31ecddc4424207eba3","uri/ipaddresses/ipv4_private.txt","7","7","1","12",
"any_ipv4_addresses","Any IPv4 Addresses","37d7a80604871e579850a658c7add2ae7557d0c6abcc9b31ecddc4424207eba3","uri/ipv4_private.txt","7","7","1","12",
"any_ipv4_addresses","Any IPv4 Addresses","838c4c2573848f58e74332341a7ca6bc5cd86a8aec7d644137d53b4d597f10f5","uri/ipaddresses/ipv4_random.txt","7","7","1","8",
"any_ipv4_addresses","Any IPv4 Addresses","838c4c2573848f58e74332341a7ca6bc5cd86a8aec7d644137d53b4d597f10f5","uri/ipv4_random.txt","7","7","1","8",
"any_ipv4_addresses","Any IPv4 Addresses","f1412386aa8db2579aff2636cb9511cacc5fd9880ecab60c048508fbe26ee4d9","uri/ipaddresses/ipv4_random.txt","6","6","1","8",
"any_ipv4_addresses","Any IPv4 Addresses","f1412386aa8db2579aff2636cb9511cacc5fd9880ecab60c048508fbe26ee4d9","uri/ipv4_random.txt","6","6","1","8",
"any_ipv4_addresses","Any IPv4 Addresses","c5eb5a4cc76a5cdb16e79864b9ccd26c3553f0c396d0a21bafb7be71c1efcd8c","uri/ipv4.txt","3","3","9","20",
```

This will be used to compare the results of the test run with the expected results, to allow online testing of custom patterns.

This is checked in the `snapshot` mode.

One issue with this is that the _earliest commit_ that a secret has been found at is reported by secret scanning, so it is not possible to cleanly define a current state of expected secrets in the repository, and test for those expected results.

## Using locally with pipenv

Install the requirements using `pipenv install`, then run `pipenv run <command>` to run the commands: `markdown`, `validate`, `snapshot`.

See [this sample script](./examples/update_custom_patterns_readme.sh) for how to update the `README.md` files for your custom patterns.

## Offline testing of Secret Scanning custom patterns

We have a test Python script, `secretscanning/test.py` that uses Intel's `hyperscan` to test custom GitHub Advanced Security Secret Scanning patterns.

This is useful for thorough testing of patterns before they are deployed, whereas the rest of the test suite is primarily designed to be run in GitHub Actions for testing in CI.

### Local test script usage

Change directory to `secretscanning`.

First run `make requirements` to install required dependencies.

``` bash
./test.py
```

By default it searches the directory above the `testing` directory for `pattern.yml` files, and tests those patterns on the same directory that file was found in.

or

``` bash
./test.py --tests <directory>
```

For full usage use `./test.py --help`

### Local test script requirements

This only works on Intel-compatible platforms, since `hyperscan` is an Intel application and written to use Intel-specific instructions.

* Python 3.9+
* `hyperscan` module, which provides Python bindings to Intel's Hyperscan
* `python-pcre` module, which provides Python bindings to libPCRE

### Development notes

Please run `make lint` after any changes

## License

This project is licensed under the terms of the MIT open source license. Please refer to the [LICENSE](LICENSE) for the full terms.

## Maintainers

See [CODEOWNERS](CODEOWNERS) for the list of maintainers.

## Support

> ℹ️ This is an _unofficial_ tool created by Field Security Services, and is not officially supported by GitHub.

See the [SUPPORT](SUPPORT.md) file.

## Background

See the [CHANGELOG](CHANGELOG.md), [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md), [SUPPORT](SUPPORT.md), [CODE OF CONDUCT](CODE_OF_CONDUCT.md) and [PRIVACY](PRIVACY.md) files for more information.
