package main

# OWASP Top 10 with Snyk Code
# To-Do: Add LDAP Injetion and verify all OWASP Top 10.
# Note: Incomplete
rule_names = {
  "HardcodedPassword": 0,
  "Ssrf": 0,
  "NoHardcodedCredentials": 0,
  "Sqli": 0,
  "NoRateLimitingForExpensiveWebOperation": 0,
  "UseCsurfForExpress": 0,
  "HTTPSourceWithUncheckedType": 0,
  "XSS": 0,
  "HardcodedSecret": 0,
  "NoHardcodedPasswords": 0,
  "InsecureHash": 0,
  "NoSqli": 0,
  "HardcodedSecret": 0,
  "PT": 0,
  "DOMXSS": 0,
  "ZipSlip": 0,
  "HardcodedNonCryptoSecret": 0,
  "JwtDecodeMethod": 0,
}

deny[msg] {
  rule = rule_value
  rule_value = rule_map[_]
  num = count([vuln | vuln = input.runs[_].tool.driver.rules[_]; vuln.name == rule_value])
  num > rule_names[rule_value]
  msg = sprintf("%s: %v is greater than the threshold of %v", [rule_value, num, rule_names[rule_value]])
}

rule_map = [
  "HardcodedPassword",
  "Ssrf",
  "NoHardcodedCredentials",
  "Sqli",
  "NoRateLimitingForExpensiveWebOperation",
  "UseCsurfForExpress",
  "HTTPSourceWithUncheckedType",
  "XSS",
  "HardcodedSecret",
  "NoHardcodedPasswords",
  "InsecureHash",
  "NoSqli",
  "HardcodedSecret",
  "PT",
  "DOMXSS",
  "ZipSlip",
  "HardcodedNonCryptoSecret",
  "JwtDecodeMethod"
]
