Create a security automation script that demonstrates programming skills and security thinking.

Multi-Scanner Orchestrator
Script that runs multiple security tools and aggregates results:

1 # Example output goal:
2 ./security-scan.py --path ./app --format json
3 # Should run SAST, dependency check, secrets scan
4 # Return unified results with pass/fail decision

Deliverables (45 min):
Working code in scripts/[Multi-Scanner_Orchestrator]/
README with usage examples
2-3 test cases or examples

lets create a simple Script that runs multiple security tools and aggregates results

Tools: checkov for secrets,dependency scanning and semgrep for sast, use the sarif file from both to aggregate the results into a json output, show failure with there are critical severity findings

create 2 examples one that doesnt fail on 3 catogries and one that fails on all 3