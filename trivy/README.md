# Trivy Scan Results

## Summary

| Image | HIGH | CRITICAL | Scan Date |
|-------|------|----------|-----------|
| nginx:alpine | X | X | DATE |
| nginx:1.14 | X | X | DATE |

## Key Findings

Document any notable CVEs found and remediation steps.

## CI Integration

Trivy is integrated into the GitHub Actions pipeline at
`.github/workflows/security-scan.yaml`. Any image with HIGH
or CRITICAL CVEs will fail the pipeline and block deployment.

## Remediation Policy

- CRITICAL CVEs: must be remediated before merge
- HIGH CVEs: must be remediated within 7 days
- MEDIUM and below: tracked but do not block deployment