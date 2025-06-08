package main

# Thresholds for severity levels
severity_thresholds = {
  "low": 10,
  "medium": 10,
  "high": 2,
  "critical": 0, # A threshold of 0 means any occurrence is a failure
}

# CWEs to exclude from counting towards thresholds
allowCWEs = {"CWE-476", "CWE-20"}

# --- Severity Count Checks (excluding allowed CWEs) ---

# Check for "low" severity vulnerabilities
deny contains msg if {
    current_severity = "low";
    # Count vulnerabilities of current_severity, EXCLUDING those with allowed CWEs
    vuln_count = count([v | 
        v = input.vulnerabilities[_]; 
        v.severity == current_severity;
        # Check if any of the vulnerability's CWEs are in the allowCWEs set
        intersecting_allowed_cwes_for_v = [id | id = v.identifiers.CWE[_]; allowCWEs[id]];
        # The vulnerability is NOT allowed (i.e., should be counted) if it has NO CWEs in the allowed list
        count(intersecting_allowed_cwes_for_v) == 0
    ]);
    vuln_count > severity_thresholds[current_severity];
    msg = sprintf("Iceman Container Policy - Severity '%s': %v found (excluding allowed CWEs), exceeds threshold %v", [current_severity, vuln_count, severity_thresholds[current_severity]])
}

# Check for "medium" severity vulnerabilities
deny contains msg if {
    current_severity = "medium";
    vuln_count = count([v | 
        v = input.vulnerabilities[_]; 
        v.severity == current_severity;
        # Check if any of the vulnerability's CWEs are in the allowCWEs set
        intersecting_allowed_cwes_for_v = [id | id = v.identifiers.CWE[_]; allowCWEs[id]];
        # The vulnerability is NOT allowed (i.e., should be counted) if it has NO CWEs in the allowed list
        count(intersecting_allowed_cwes_for_v) == 0
    ]);
    vuln_count > severity_thresholds[current_severity];
    msg = sprintf("Iceman Container Policy - Severity '%s': %v found (excluding allowed CWEs), exceeds threshold %v", [current_severity, vuln_count, severity_thresholds[current_severity]])
}

# Check for "high" severity vulnerabilities
deny contains msg if {
    current_severity = "high";
    vuln_count = count([v | 
        v = input.vulnerabilities[_]; 
        v.severity == current_severity;
        # Check if any of the vulnerability's CWEs are in the allowCWEs set
        intersecting_allowed_cwes_for_v = [id | id = v.identifiers.CWE[_]; allowCWEs[id]];
        # The vulnerability is NOT allowed (i.e., should be counted) if it has NO CWEs in the allowed list
        count(intersecting_allowed_cwes_for_v) == 0
    ]);
    vuln_count > severity_thresholds[current_severity];
    msg = sprintf("Iceman Container Policy - Severity '%s': %v found (excluding allowed CWEs), exceeds threshold %v", [current_severity, vuln_count, severity_thresholds[current_severity]])
}

# Check for "critical" severity vulnerabilities
deny contains msg if {
    current_severity = "critical";
    vuln_count = count([v | 
        v = input.vulnerabilities[_]; 
        v.severity == current_severity;
        # Check if any of the vulnerability's CWEs are in the allowCWEs set
        intersecting_allowed_cwes_for_v = [id | id = v.identifiers.CWE[_]; allowCWEs[id]];
        # The vulnerability is NOT allowed (i.e., should be counted) if it has NO CWEs in the allowed list
        count(intersecting_allowed_cwes_for_v) == 0
    ]);
    vuln_count > severity_thresholds[current_severity];
    msg = sprintf("Iceman Container Policy - Severity '%s': %v found (excluding allowed CWEs), exceeds threshold %v (any occurrence is a failure)", [current_severity, vuln_count, severity_thresholds[current_severity]])
}
