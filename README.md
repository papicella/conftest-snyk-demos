# Conftest Snyk Demos

The following demos show how to use [conftest](https://www.conftest.dev/) with Snyk to break builds based on certain conditions.

Conftest is a utility to help you write tests against structured configuration data. For instance, you could write tests for your Kubernetes configurations, Tekton pipeline definitions, Terraform code, Serverless configs or any other structured data. In this case we are using JSON return result set from a snyk container, open-source and code test

## Pre Requistes

* [Snyk CLI](https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli) 
* Maven to build the required source code example in order to run a snyk test
* [conftest](https://www.conftest.dev/)

## Container Test

The following demo using the JSON return result set from a snyk container test against a rego policy file to break a build based on the policy file conditions.

- cd into "**simple-container-demo**" directory as shown below

```shell
$ cd simple-demo-container
```

- view the file "**./policy/main.rego**" file and view it's contents

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

1. Conftest relies on the Rego language from Open Policy Agent for writing policies.
2. thresholds data structure defines how many vulnerabilities of severity type are allowed before we fail the policy test
3. this demo has a single deny block but you could add more

- Test it as follows

```shell
$ snyk container test registry.access.redhat.com/ubi8/ubi:8.7 --json | conftest test -
FAIL - - main - high: 10 is greater than the threshold of 2
FAIL - - main - low: 141 is greater than the threshold of 10
FAIL - - main - medium: 90 is greater than the threshold of 10

3 tests, 0 passed, 0 warnings, 3 failures, 0 exceptions
```

## SCA / Open-Source Test

The following demo uses a snyk test JSON result set against a rego policy file to break a build based on the policy file conditions.

Note: The following demos include two REGO policy files so we will specify which one to use for each run shortly.

- cd into the "**sca-test**" folder as shown below

```shell
$ cd sca-test
```

- View both policy files as shown below. 

```shell
$ ls -la ./policy
total 16
drwxr-xr-x  4 pasapicella  staff   128  2 Sep 23:07 .
drwxr-xr-x  6 pasapicella  staff   192  3 Sep 18:10 ..
-rw-r--r--  1 pasapicella  staff  1163  2 Sep 23:06 exploit-and-severity-count-test.rego
-rw-r--r--  1 pasapicella  staff   603  2 Sep 22:53 exploit-test.rego
```

- For this demo we are going to use the "exploit-and-severity-count-test.rego", inspect the file as follows.

_Note: This policy file will fail for severity thresholds hit or exploit thresholds hit_

```python
package main

# Set these to the number you require. The policy will fail if it finds more vulnerabilities for the given exploit
exploits = {
  "Proof of Concept": 5,
  "Not Defined": 100,
  "Functional": 1,
  "Mature": 0,
}

# Set these to the number you require. The policy will fail if it finds more vulnerabilities for the given severity
thresholds = {
  "low": 10,
  "medium": 5,
  "high": 2,
  "critical": 0,
}

deny[msg] {
  exploit = exploit_value
  exploit_value = exploit_map[_]
  num = count([vuln | vuln = input.vulnerabilities[_]; vuln.exploit == exploit_value])
  num > exploits[exploit_value]
  msg = sprintf("%s: %v is greater than the threshold of %v", [exploit_value, num, exploits[exploit_value]])
}

exploit_map = ["Proof of Concept", "Not Defined", "Functional", "Mature"]

deny[msg] {
  severity = severity_value
  severity_value = severity_map[_]
  num = count([vuln | vuln = input.vulnerabilities[_]; vuln.severity == severity_value])
  num > thresholds[severity_value]
  msg = sprintf("%s: %v is greater than the threshold of %v", [severity_value, num, thresholds[severity_value]])
}

severity_map = ["low", "medium", "high", "critical"]
```

- Ensure that snyk test will work against the source code "**./snyk-boot-web**". It includes a pom.xml so you would need to build the code to generate a dependancy tree 

```shell
$ cd snyk-boot-web
$ mvn package 
$ cd ..
```

- Run it as follows

_Note: Here we specify the REGO policy file we wish to use_

```shell
$ snyk test --json ./snyk-boot-web | conftest test --policy=./policy/exploit-and-severity-count-test.rego -
FAIL - - main - Proof of Concept: 12 is greater than the threshold of 5
FAIL - - main - critical: 3 is greater than the threshold of 0
FAIL - - main - high: 9 is greater than the threshold of 2
FAIL - - main - medium: 23 is greater than the threshold of 5

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

## Snyk Code Test

The following demo uses a snyk code test JSON result set to look for rule based vulnerabilities over a certain threshold

- cd into the "**code-test**" folder as shown below
- 
```shell
$ cd code-test
```

- View the policy ./policy/main.rego as shown below

```python
package main

# Set these to the number you require. The policy will fail if it finds a single vulverability defined as either of the following
rule_names = {
  "HardcodedPassword": 0,
  "Sqli": 0
}

deny[msg] {
  rule = rule_value
  rule_value = rule_map[_]
  num = count([vuln | vuln = input.runs[_].tool.driver.rules[_]; vuln.name == rule_value])
  num > rule_names[rule_value]
  msg = sprintf("%s: %v is greater than the threshold of %v", [rule_value, num, rule_names[rule_value]])
}

rule_map = ["HardcodedPassword", "Sqli"]
```

_Note: THis policy file simply checks if we have at least 1 Sql Injection or Hardcode Password Rule Vulnerability. The full rule set of snyk code is [here](https://docs.snyk.io/scan-applications/snyk-code/security-rules-used-by-snyk-code)_

- Run it as follows

```shell
$ snyk code test --json ../sca-test/snyk-boot-web | conftest test -
FAIL - - main - HardcodedPassword: 1 is greater than the threshold of 0
FAIL - - main - Sqli: 1 is greater than the threshold of 0

2 tests, 0 passed, 0 warnings, 2 failures, 0 exceptions
```

<hr />
Pas Apicella [pas at snyk.io] is a Principal Solution Engineer at Snyk APJ 
