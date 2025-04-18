# Ballerina OWASP Top 10 Mapped Rules

This repository contains a collection of rules and best practices for the Ballerina language that are mapped to the OWASP Top 10 security risks. These rules help developers write more secure code by identifying common vulnerabilities and providing guidance on how to avoid them.

## What is Ballerina?

[Ballerina](https://ballerina.io/) is an open-source programming language designed for integration. It makes it easier to write microservices and integrations by providing built-in networking abstractions along with a focus on safety and security.

## OWASP Top 10 and Ballerina

The [OWASP Top 10](https://owasp.org/Top10/) is a standard awareness document for developers that represents a broad consensus about the most critical security risks to web applications. This repository maps these risks to Ballerina programming practices and provides rules to mitigate them.

## Installation and Usage

To use these rules in your Ballerina project:

1. Clone this repository:

   ```bash
   git clone https://github.com/nureka-rodrigo/Ballerina-OWASP-Top-10-Mapped-Rules.git
   ```

2. Follow the individual rule documentation for implementation details.

## Mapped Rules

01. [Server-side requests should not be vulnerable to traversing attacks](./Not-Covered/01/README.md)
02. [Accessing files should not lead to filesystem oracle attacks](README.md)
03. [Environment variables should not be defined from untrusted input](./Not-Covered/03/README.md)
04. [Credentials should not be hard-coded](./Not-Covered/04/README.md)
05. [Counter Mode initialization vectors should not be reused](./Not-Covered/05/README.md)
06. [XML operations should not be vulnerable to injection attacks](README.md)
07. [JSON operations should not be vulnerable to injection attacks](./Not-Covered/07/README.md)
08. [Thread suspensions should not be vulnerable to Denial of Service attacks](README.md)
09. [Components should not be vulnerable to intent redirection](README.md)
10. [XML signatures should be validated securely](README.md)
11. [XML parsers should not be vulnerable to Denial of Service attacks](README.md)
12. [XML parsers should not load external schemas](README.md)
13. [XML parsers should not allow inclusion of arbitrary files](README.md)
14. [Mobile database encryption keys should not be disclosed](README.md)
15. [Applications should not create session cookies from untrusted input](./Not-Covered/15/README.md)
16. [Reflection should not be vulnerable to injection attacks](README.md)
17. [Extracting archives should not lead to zip slip vulnerabilities](README.md)
18. [OS commands should not be vulnerable to argument injection attacks](README.md)
19. [A new session should be created during user authentication](README.md)
20. [Authorizations should be based on strong decisions](README.md)
21. [OpenSAML2 should be configured to prevent authentication bypass](README.md)
22. [JWT should be signed and verified with strong cipher algorithms](README.md)
23. [Cipher algorithms should be robust](README.md)
24. [Encryption algorithms should be used with secure mode and padding scheme](./Not-Covered/24/README.md)
25. [Server hostnames should be verified during SSL/TLS connections](./Not-Covered/25/README.md)
26. [Server-side templates should not be vulnerable to injection attacks](README.md)
27. [Insecure temporary file creation methods should not be used](README.md)
28. [Passwords should not be stored in plaintext or with a fast hashing algorithm](README.md)
29. [Dynamic code execution should not be vulnerable to injection attacks](README.md)
30. ["ActiveMQConnectionFactory" should not be vulnerable to malicious code deserialization](README.md)
31. [NoSQL operations should not be vulnerable to injection attacks](README.md)
32. [HTTP request redirections should not be open to forging attacks](./Not-Covered/32/README.md)
33. [Logging should not be vulnerable to injection attacks](README.md)
34. [Server-side requests should not be vulnerable to forging attacks](README.md)
35. [Deserialization should not be vulnerable to injection attacks](README.md)
36. [Endpoints should not be vulnerable to reflected cross-site scripting (XSS) attacks](README.md)
37. [Server certificates should be verified during SSL/TLS connections](README.md)
38. [Persistent entities should not be used as arguments of "@RequestMapping" methods](README.md)
39. ["HttpSecurity" URL patterns should be correctly ordered](README.md)
40. [LDAP connections should be authenticated](README.md)
41. [Cryptographic keys should be robust](README.md)
42. [Weak SSL/TLS protocols should not be used](README.md)
43. [Secure random number generators should not output predictable values](README.md)
44. [Database queries should not be vulnerable to injection attacks](README.md)
45. [Cipher Block Chaining IVs should be unpredictable](README.md)
46. [XML parsers should not be vulnerable to XXE attacks](README.md)
47. [Classes should not be loaded dynamically](README.md)
48. [Basic authentication should not be used](README.md)
49. [Regular expressions should not be vulnerable to Denial of Service attacks](README.md)
50. ["HttpServletRequest.getRequestedSessionId()" should not be used](README.md)
51. [A secure password should be used when connecting to a database](README.md)
52. [XPath expressions should not be vulnerable to injection attacks](README.md)
53. [I/O function calls should not be vulnerable to path injection attacks](./Not-Covered/53/README.md)
54. [LDAP queries should not be vulnerable to injection attacks](README.md)
55. [OS commands should not be vulnerable to command injection attacks](README.md)
56. [Password hashing functions should use an unpredictable salt](README.md)
57. [Exceptions should not be thrown from servlet methods](README.md)
58. [Stack traces should not be disclosed](./Not-Covered/58/README.md)
