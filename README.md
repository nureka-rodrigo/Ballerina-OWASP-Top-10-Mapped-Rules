# Ballerina OWASP Top 10 Mapped Rules

This repository contains a collection of rules and best practices for the Ballerina language that are mapped to the OWASP Top 10 security risks. These rules help developers write more secure code by identifying common vulnerabilities and providing guidance on how to avoid them.

## What is Ballerina?

[Ballerina](https://ballerina.io/) is an open-source programming language designed for integration. It makes it easier to write microservices and integrations by providing built-in networking abstractions along with a focus on safety and security.

## OWASP Top 10 and Ballerina

The [OWASP Top 10](https://owasp.org/Top10/) is a standard awareness document for developers that represents a broad consensus about the most critical security risks to web applications. This repository maps these risks to Ballerina programming practices and provides rules to mitigate them.

## Mapped Rules

### A01:2021 – Broken Access Control

- **ballerina/io:1**: I/O function calls should not be vulnerable to path injection attacks

### A02:2021 – Cryptographic Failures

### A03:2021 – Injection

### A04:2021 – Insecure Design

### A05:2021 – Security Misconfiguration

### A06:2021 – Vulnerable and Outdated Components

### A07:2021 – Identification and Authentication Failures

### A08:2021 – Software and Data Integrity Failures

### A09:2021 – Security Logging and Monitoring Failures

### A10:2021 – Server-Side Request Forgery

## Installation and Usage

To use these rules in your Ballerina project:

1. Clone this repository:
   ```
   git clone https://github.com/nureka-rodrigo/Ballerina-OWASP-Top-10-Mapped-Rules.git
   ```

2. Follow the individual rule documentation for implementation details.

3. Consider integrating with Ballerina's static analysis tool for automated checking.
