# Security Policy

## Supported Versions

We actively support the following versions of SchemaPin with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities to us via email at:

**security@thirdkey.ai**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information in your report:

- Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

## Security Response Process

1. **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours.

2. **Investigation**: Our security team will investigate the issue and determine its severity and impact.

3. **Fix Development**: We will develop a fix for the vulnerability, prioritizing based on severity.

4. **Coordinated Disclosure**: We will coordinate with you on the disclosure timeline, typically:
   - Critical vulnerabilities: 7-14 days
   - High severity: 30 days
   - Medium/Low severity: 60-90 days

5. **Release**: We will release a security update and publish a security advisory.

6. **Credit**: We will credit you in our security advisory (unless you prefer to remain anonymous).

## Security Best Practices

When using SchemaPin in your projects:

### Key Management
- Store private keys securely using hardware security modules (HSMs) or secure key management services
- Never commit private keys to version control
- Rotate keys regularly according to your security policy
- Use strong, randomly generated keys

### Verification
- Always verify signatures before trusting schema content
- Implement proper error handling for verification failures
- Use the latest version of SchemaPin to ensure you have security updates
- Enable key pinning in production environments

### Network Security
- Use HTTPS for all schema discovery requests
- Implement certificate pinning for critical domains
- Consider using a Content Delivery Network (CDN) for schema distribution

### Monitoring
- Monitor for unexpected schema changes
- Log all verification attempts and failures
- Set up alerts for key rotation events
- Regularly audit your pinned keys

## Cryptographic Security

SchemaPin uses industry-standard cryptographic algorithms:

- **Digital Signatures**: ECDSA with P-256 curve (secp256r1)
- **Hashing**: SHA-256 for content hashing and key fingerprints
- **Key Format**: PEM-encoded keys following RFC 5915 and RFC 5480

### Security Considerations
- ECDSA P-256 provides approximately 128 bits of security
- SHA-256 provides 256 bits of security against collision attacks
- All cryptographic operations use constant-time implementations where possible

## Vulnerability Disclosure Policy

We believe in responsible disclosure and will work with security researchers to:

- Acknowledge legitimate security reports within 48 hours
- Provide regular updates on our progress
- Credit researchers in our security advisories
- Maintain confidentiality until fixes are released

## Security Updates

Security updates are released as:

- **Patch releases** (e.g., 1.1.1 → 1.1.2) for security fixes
- **GitHub Security Advisories** for vulnerability notifications
- **Release notes** documenting security improvements

Subscribe to our releases on GitHub to receive notifications of security updates.

## Contact

For security-related questions or concerns:

- **Email**: security@thirdkey.ai
- **PGP Key**: Available on request
- **Response Time**: Within 48 hours

For general questions about SchemaPin:

- **GitHub Issues**: For non-security related bugs and feature requests
- **Email**: contact@thirdkey.ai