package main

# OWASP Top 10 with Snyk Code
# To-Do: Add LDAP Injetion and verify all OWASP Top 10.
# Note: Incomplete. Thresholds for specific Snyk Code rule names. A threshold of 0 means any occurrence is a failure.
rule_thresholds = {
  "HardcodedPassword": 0,
  "Ssrf": 0,
  "NoHardcodedCredentials": 0,
  "Sqli": 0,
  "NoRateLimitingForExpensiveWebOperation": 0,
  "UseCsurfForExpress": 0,
  "HTTPSourceWithUncheckedType": 0,
  "XSS": 0,
  "HardcodedSecret": 0, # Note: Duplicate key in original, will be one entry in the map
  "NoHardcodedPasswords": 0,
  "InsecureHash": 0,
  "NoSqli": 0,
  # "HardcodedSecret": 0, # This was a duplicate in the original list
  "PT": 0, # Path Traversal
  "DOMXSS": 0,
  "ZipSlip": 0,
  "HardcodedNonCryptoSecret": 0,
  "JwtDecodeMethod": 0,
}

# Helper function to generate deny rules (conceptual, as Rego doesn't have dynamic rule generation like this for OPA 1.5)
# We will manually create each rule as required by the older OPA version.

# --- Individual Rule Checks ---

# Check for "HardcodedPassword"
deny contains msg if {
    current_rule_name = "HardcodedPassword";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "Ssrf"
deny contains msg if {
    current_rule_name = "Ssrf";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "NoHardcodedCredentials"
deny contains msg if {
    current_rule_name = "NoHardcodedCredentials";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "Sqli"
deny contains msg if {
    current_rule_name = "Sqli";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "NoRateLimitingForExpensiveWebOperation"
deny contains msg if {
    current_rule_name = "NoRateLimitingForExpensiveWebOperation";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "UseCsurfForExpress"
deny contains msg if {
    current_rule_name = "UseCsurfForExpress";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "HTTPSourceWithUncheckedType"
deny contains msg if {
    current_rule_name = "HTTPSourceWithUncheckedType";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "XSS"
deny contains msg if {
    current_rule_name = "XSS";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "HardcodedSecret"
deny contains msg if {
    current_rule_name = "HardcodedSecret";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "NoHardcodedPasswords"
deny contains msg if {
    current_rule_name = "NoHardcodedPasswords";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "InsecureHash"
deny contains msg if {
    current_rule_name = "InsecureHash";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "NoSqli"
deny contains msg if {
    current_rule_name = "NoSqli";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "PT" (Path Traversal)
deny contains msg if {
    current_rule_name = "PT";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "DOMXSS"
deny contains msg if {
    current_rule_name = "DOMXSS";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "ZipSlip"
deny contains msg if {
    current_rule_name = "ZipSlip";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "HardcodedNonCryptoSecret"
deny contains msg if {
    current_rule_name = "HardcodedNonCryptoSecret";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "JwtDecodeMethod"
deny contains msg if {
    current_rule_name = "JwtDecodeMethod";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("OWASP Rule '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}
