## Broken Access Control

### Overview

This directory contains rules related to the ***OWASP Top 10 2021*** category ***A01: Broken Access Control***. Broken access control refers to failures in correctly enforcing restrictions on what authenticated users are allowed to do, potentially leading to unauthorized information disclosure, modification, or destruction of data.

## Common Vulnerabilities

Broken access control vulnerabilities include:

- Path traversal vulnerabilities
- Unauthorized access to API endpoints
- Privilege escalation
- Metadata manipulation (e.g., JWT tampering)
- CORS misconfiguration
- Force browsing to authenticated pages

## Recommendations

To prevent broken access control:

- Implement proper authorization checks at each step
- Use the principle of least privilege
- Deny by default, then allow specific permissions
- Validate and sanitize all user inputs
- Implement proper session management
- Use secure coding practices specific to access control

## Learn More

For more information, refer to:

- [OWASP Top 10 2021 - A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)