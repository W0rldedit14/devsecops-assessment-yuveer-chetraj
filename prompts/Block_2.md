Pipeline Security

Implement security-integrated CI/CD using GitHub Actions.
Requirements:
Create .github/workflows/secure-pipeline.yml
Integrate 2+ security scanners of your choice, we will use semgrep(sast), checkov(secret,iac),trivy(sca)
Implement quality gates that fail the build appropriately, we will fail on crits
Handle security findings (fail/warn/pass logic) warn on highs

Deliverables (45 min):
Working GitHub Actions workflow
Brief documentation of security controls
Example of how quality gates work

lets keep iy simple, i think the sarif route is still the best route