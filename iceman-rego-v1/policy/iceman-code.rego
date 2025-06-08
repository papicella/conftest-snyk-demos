package main

# Thresholds for specific Snyk Code rule names. A threshold of 0 means any occurrence is a failure.
# Policy checks for No SSRF, XSS, SQLi, or Hardcoded Passwords.
rule_thresholds = {
  "HardcodedPassword": 0,
  "Sqli": 0,
  "Ssrf": 0,
  "Xss": 0
}

# Check for "HardcodedPassword"
deny contains msg if {
    current_rule_name = "HardcodedPassword";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("Iceman Code Policy - '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "Sqli"
deny contains msg if {
    current_rule_name = "Sqli";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("Iceman Code Policy - '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "Ssrf"
deny contains msg if {
    current_rule_name = "Ssrf";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("Iceman Code Policy - '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "Xss"
deny contains msg if {
    current_rule_name = "Xss";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("Iceman Code Policy - '%s': %v found, exceeds threshold %v", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}
