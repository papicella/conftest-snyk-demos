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
