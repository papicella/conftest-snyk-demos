package main

# Thresholds for specific Snyk Code rule names. A threshold of 0 means any occurrence is a failure.
rule_thresholds = {
  "HardcodedPassword": 0,
  "Sqli": 0
}

# Check for "HardcodedPassword"
deny contains msg if {
    current_rule_name = "HardcodedPassword";
    # Count occurrences of this rule name in the input
    # The path to rule names is input.runs[r].tool.driver.rules[i].name
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("Snyk Code rule '%s' found: %v occurrences. Threshold is %v (any occurrence is a failure).", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}

# Check for "Sqli" (SQL Injection)
deny contains msg if {
    current_rule_name = "Sqli";
    rule_count = count([rule | run = input.runs[_]; rule = run.tool.driver.rules[_]; rule.name == current_rule_name]);
    rule_count > rule_thresholds[current_rule_name];
    msg = sprintf("Snyk Code rule '%s' found: %v occurrences. Threshold is %v (any occurrence is a failure).", [current_rule_name, rule_count, rule_thresholds[current_rule_name]])
}
