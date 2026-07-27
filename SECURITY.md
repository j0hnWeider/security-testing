# 🔒 Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | ✅ Active development |
| 1.x     | ❌ No longer supported |

## Reporting a Vulnerability

We take the security of this project seriously. If you believe you have found a security vulnerability, please follow these steps:

### 📧 How to Report

1. **DO NOT** open a public GitHub issue for the vulnerability.
2. Send a detailed report to the repository maintainer via [GitHub Security Advisories](https://github.com/j0hnWeider/security-testing/security/advisories) (preferred) or open a private vulnerability report.
3. Include the following information:
   - Type of vulnerability (e.g., SQL injection, XSS, authentication bypass)
   - Steps to reproduce
   - Expected vs actual behavior
   - Potential impact
   - Any suggested fixes (if applicable)

### ⏱️ Response Timeline

| Timeframe | Action |
|-----------|--------|
| **24 hours** | Initial acknowledgment of receipt |
| **3-5 days** | Preliminary assessment and risk classification |
| **7-14 days** | Patch development and testing |
| **14-21 days** | Public disclosure (if applicable) |

### 🏷️ Risk Classification

| Severity | Response Time | Examples |
|----------|--------------|----------|
| 🔴 **Critical** | 24h patch | RCE, SQL injection, auth bypass |
| 🟠 **High** | 3-5 days | XSS, privilege escalation, sensitive data exposure |
| 🟡 **Medium** | 7-14 days | DoS, partial information disclosure |
| 🟢 **Low** | 14-30 days | Missing security headers, minor config issues |

## 🔐 Security Best Practices

When contributing to this project, please follow these guidelines:

### Code Security
- Never commit sensitive data (API keys, tokens, passwords)
- Use environment variables for all secrets
- Validate and sanitize all user inputs in test payloads
- Follow OWASP Top 10 guidelines
- Run `npm run lint` before committing

### Repository Security
- Enable branch protection on `main`/`master`
- Require PR reviews for all changes
- Use signed commits where possible
- Keep dependencies up to date
- Enable Dependabot alerts

### Pipeline Security
- Never run untrusted code in CI/CD
- Use principle of least privilege for tokens
- Pin versions of actions and dependencies
- Review all artifact uploads for sensitive data

## 🔄 Disclosure Process

1. **Private report received** → Maintainer acknowledges within 24h
2. **Vulnerability confirmed** → Patch developed (priority based on severity)
3. **Patch released** → New version published
4. **Public disclosure** → 30 days after patch release

## 🛡️ OWASP Alignment

This project's security tests align with:

- **OWASP Top 10 (2021)** — All categories covered
- **OWASP ASVS** — Level 2 (Standard) compliance targeted
- **OWASP Secure Headers Project** — Full coverage
- **OWASP ZAP** — DAST scanning integrated

---

*We appreciate your help in keeping this project secure!*

