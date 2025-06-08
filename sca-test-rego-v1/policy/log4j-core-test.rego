package main

# Thresholds for specific CVEs. A threshold of 0 means any occurrence is a failure.
cve_thresholds = {
  "CVE-2021-45046": 0,
  "CVE-2021-45105": 0,
  "CVE-2021-44832": 0
}

# Check for CVE-2021-45046
deny contains msg if {
    current_cve = "CVE-2021-45046";
    # Count occurrences of this CVE in the input vulnerabilities
    # Each vulnerability's CVE list is input.vulnerabilities[i].identifiers.CVE
    cve_count = count([cve_id | vuln = input.vulnerabilities[_]; cve_id = vuln.identifiers.CVE[_]; cve_id == current_cve]);
    cve_count > cve_thresholds[current_cve];
    msg = sprintf("Log4j CVE %s found: %v occurrences. Threshold is %v (any occurrence is a failure).", [current_cve, cve_count, cve_thresholds[current_cve]])
}

# Check for CVE-2021-45105
deny contains msg if {
    current_cve = "CVE-2021-45105";
    cve_count = count([cve_id | vuln = input.vulnerabilities[_]; cve_id = vuln.identifiers.CVE[_]; cve_id == current_cve]);
    cve_count > cve_thresholds[current_cve];
    msg = sprintf("Log4j CVE %s found: %v occurrences. Threshold is %v (any occurrence is a failure).", [current_cve, cve_count, cve_thresholds[current_cve]])
}

# Check for CVE-2021-44832
deny contains msg if {
    current_cve = "CVE-2021-44832";
    cve_count = count([cve_id | vuln = input.vulnerabilities[_]; cve_id = vuln.identifiers.CVE[_]; cve_id == current_cve]);
    cve_count > cve_thresholds[current_cve];
    msg = sprintf("Log4j CVE %s found: %v occurrences. Threshold is %v (any occurrence is a failure).", [current_cve, cve_count, cve_thresholds[current_cve]])
}
