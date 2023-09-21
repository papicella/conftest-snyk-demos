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
