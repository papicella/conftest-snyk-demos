# Conftest Snyk Demos

The following demos show how to use [conftest](https://www.conftest.dev/) with Snyk to break builds based on certain conditions.

[Conftest](https://www.conftest.dev/) is a utility to help you write tests against structured configuration data. For instance, you could write tests for your Kubernetes configurations, Tekton pipeline definitions, Terraform code, Serverless configs or any other structured data. In this case we are using JSON return result set from a snyk container, open-source and code test using the Snyk CLI.

These demos are using Open Policy Agent and the Conftest CLI:
* [https://www.conftest.dev/](https://www.conftest.dev/)
* [https://github.com/open-policy-agent/conftest](https://github.com/open-policy-agent/conftest)

## Pre Requistes

* [Snyk Account](https://app.snyk.io)
* [Snyk CLI](https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli) 
* [Maven](https://maven.apache.org/) to build the required source code example in order to run a snyk test - Only for Open-Source test
* [conftest](https://www.conftest.dev/)


## Container Test

The following demo using the JSON return result set from a snyk container test against a Rego policy file to break a build based on the policy file conditions.

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
2. Thresholds data structure defines how many vulnerabilities of severity type are allowed before we fail the policy test
3. This demo has a single deny block, but you could add more which we will do on the next demo

- Test it as follows

```shell
$ snyk container test registry.access.redhat.com/ubi8/ubi:8.7 --json | conftest test -
FAIL - - main - high: 10 is greater than the threshold of 2
FAIL - - main - low: 141 is greater than the threshold of 10
FAIL - - main - medium: 90 is greater than the threshold of 10

3 tests, 0 passed, 0 warnings, 3 failures, 0 exceptions
```

## SCA / Open-Source Test

### exploit-and-severity-count-test.rego 

The following demo uses a snyk test JSON result set against a Rego policy file to break a build based on the policy file conditions.

_Note: The following demos include three Rego policy files, so we will specify which one to use for each run shortly._

- cd into the "**sca-test**" folder as shown below

```shell
$ cd sca-test
```

- View both policy files as shown below. 

```shell
$ ls -la ./policy
total 24
drwxr-xr-x  5 pasapicella  staff   160  4 Sep 16:37 .
drwxr-xr-x  8 pasapicella  staff   256  4 Sep 16:39 ..
-rw-r--r--  1 pasapicella  staff  1163  2 Sep 23:06 exploit-and-severity-count-test.rego
-rw-r--r--  1 pasapicella  staff   603  2 Sep 22:53 exploit-test.rego
-rw-r--r--  1 pasapicella  staff   545  4 Sep 16:37 log4j-core-test.rego
```

- For this demo we are going to use the "**exploit-and-severity-count-test.rego**", inspect the file as follows.

_Note: This policy file will fail for severity thresholds hit or exploit thresholds hit as defined below._

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

_Note: Here we specify the Rego policy file we wish to use with the flag **--policy**_

```shell
$ snyk test --json ./snyk-boot-web | conftest test --policy=./policy/exploit-and-severity-count-test.rego -
FAIL - - main - Proof of Concept: 12 is greater than the threshold of 5
FAIL - - main - critical: 3 is greater than the threshold of 0
FAIL - - main - high: 9 is greater than the threshold of 2
FAIL - - main - medium: 23 is greater than the threshold of 5

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```

### log4j-core-test.rego

In this next demo we look for a specific set of CVE's and if we find any of those we will break the build. Basically we are making sure a set of 3 log4j-core CVE's do not exist in the snyk test output

* CVE-2021-45046
* CVE-2021-45105
* CVE-2021-44832

- Take a look at the policy file "**./policy/log4j-core-test.rego**" as shown below

```python
package main

# Set these to the number you require. The policy will fail if it finds  any one of these CVE's in the snyk test
cves = {
  "CVE-2021-45046": 0,
  "CVE-2021-45105": 0,
  "CVE-2021-44832": 0
}

deny[msg] {
  cve = cve_value
  cve_value = cve_map[_]
  num = count([vuln | vuln = input.vulnerabilities[_].identifiers.CVE[_]; vuln == cve_value])
  num > cves[cve_value]
  msg = sprintf("%s: %v is greater than the threshold of %v", [cve_value, num, cves[cve_value]])
}

cve_map = ["CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"]
```

- Run it as follows. From here you can see each CVE came up at least once so this will fail the policy check as desired

```shell
$ snyk test --json ./snyk-boot-web | conftest test --policy=./policy/log4j-core-test.rego -
FAIL - - main - CVE-2021-44832: 1 is greater than the threshold of 0
FAIL - - main - CVE-2021-45046: 1 is greater than the threshold of 0
FAIL - - main - CVE-2021-45105: 1 is greater than the threshold of 0

3 tests, 0 passed, 0 warnings, 3 failures, 0 exceptions
```

This example showed how you can inspect each element in the CVE array output against a list of CVE's we wish to check for. You could easily adapat this demo to include CWE's or even any other data you wish to use

## Snyk Code Test

The following demo uses a snyk code test JSON result set to look for rule based vulnerabilities over a certain threshold

- cd into the "**code-test**" folder as shown below

```shell
$ cd code-test
```

- View the policy "**./policy/main.rego**" as shown below

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

_Note: This policy file simply checks if we have at least 1 Sql Injection or Hardcode Password Rule Vulnerability. You can add further rules and increase the thresholds rather than just break the policy on a single vuln as shown in the examples above._

Ie:

```python
rule_names = {
  "HardcodedPassword": 3,
  "Sqli": 2
}
```

The full rule set of snyk code is [here](https://docs.snyk.io/scan-applications/snyk-code/security-rules-used-by-snyk-code)

- Run it as follows. Here there is only a single Rego policy file, so we don't need to specify which one we are using here

```shell
$ snyk code test --json ../sca-test/snyk-boot-web | conftest test -
FAIL - - main - HardcodedPassword: 1 is greater than the threshold of 0
FAIL - - main - Sqli: 1 is greater than the threshold of 0

2 tests, 0 passed, 0 warnings, 2 failures, 0 exceptions
```

If you're unsure what exactly a policy is, or unfamiliar with the Rego policy language, the [Policy Language documentation](https://www.openpolicyagent.org/docs/latest/policy-language/) provided by the Open Policy Agent documentation site is a great resource to read

## Iceman Demo

Iceman-web is a self-contained demo for Snyk Opensource, Snyk code and Snyk container - All in one go. To make use of the iceman demo, please do the following:

1. Navigate to iceman subdirectory. Policies are defined in the policy sub-dir under iceman sub-dir. Make changes to individual policies as you see fit.
2. To run iceman demo, Execute the bash script `iceman.sh`. Optionally change the execution cycles based-off your needs. Current sequence is opensource -> code -> container.
3. under the iceman sub-dir, iceman-web has got package.json manifest file, Next.JS javascript mainly under the app directory and a Dockerfile for the Next.JS app.

> **_NOTE:_**  The repo is for training & testing purposes only. Please do not use the contents for anything production use. Contributions are welcome.

<hr />
Pas Apicella [pas at snyk.io] is a Principal Solution Engineer at Snyk APJ 
