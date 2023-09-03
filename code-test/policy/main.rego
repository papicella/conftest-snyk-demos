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
