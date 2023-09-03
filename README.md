# Conftest Snyk Demos

The following demos show how to use [conftest](https://www.conftest.dev/) with Snyk to break builds based on certain conditions.

Conftest is a utility to help you write tests against structured configuration data. For instance, you could write tests for your Kubernetes configurations, Tekton pipeline definitions, Terraform code, Serverless configs or any other structured data. In this case we are using JSON return result set from a snyk container, open-source and code test

## Pre Requistes

* [Snyk CLI](https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli) 
* Maven to build the required source code example in order to run a snyk test
* [conftest](https://www.conftest.dev/)

## Container Test

- cd into "**simple-container-demo**" directory as shown below

```shell
$ cd simple-demo-container
```

- view the file ./policy/main.rego file and view it's contents

```python
package main

# Set these to the number you require. The policy will fail if it finds more vulnerabilities for the given severity
thresholds = {
  "low": 10,
  "medium": 10,
  "high": 2,
  "critical": 0,
}

# You can not count certain types of vulnerabilties towards the thresholds
allowCWEs = {"CWE-476", "CWE-20"}

deny[msg] {
  severity = severity_value
  severity_value = severity_map[_]
  num = count([vuln | vuln = input.vulnerabilities[_]; vuln.severity == severity_value])
  num > thresholds[severity_value]
  msg = sprintf("%s: %v is greater than the threshold of %v", [severity_value, num, thresholds[severity_value]])
}

severity_map = ["low", "medium", "high", "critical"]
```

_Few things to note here_

Conftest relies on the Rego language from Open Policy Agent for writing policies.
thresholds data structure defines how many vulnerabilities of severity type are allowed before we fail the policy test
this demo has a single deny block but you could add more

- Test it as follows

```shell
$ snyk container test registry.access.redhat.com/ubi8/ubi:8.7 --json | conftest test -
FAIL - - main - high: 10 is greater than the threshold of 2
FAIL - - main - low: 141 is greater than the threshold of 10
FAIL - - main - medium: 90 is greater than the threshold of 10

3 tests, 0 passed, 0 warnings, 3 failures, 0 exceptions
```

## SCA / Open-Source Test

## Snyk Code Test


<hr />
Pas Apicella [pas at snyk.io] is a Principal Solution Engineer at Snyk APJ 
