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
