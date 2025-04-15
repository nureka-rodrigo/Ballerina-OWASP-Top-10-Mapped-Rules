## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | Environment variables should not be defined from untrusted input |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)<br>[A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| **Mapped CWEs** | [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)<br>[CWE-454: External Initialization of Trusted Variables or Data Stores](https://cwe.mitre.org/data/definitions/454.html) |

## Description

Environment variables are often used to store sensitive configuration data, credentials, and application settings. When applications allow untrusted input to define or modify environment variables without proper validation, they can introduce significant security risks.

Using untrusted input to set environment variables can lead to various attacks:

- Command injection through environment variable manipulation
- Overriding secure configurations with malicious values
- Cross-process information disclosure
- Privilege escalation by altering environment variables used by other processes
- Poisoning of configuration data that might be used for security decisions

These vulnerabilities are particularly concerning because environment variables are often globally accessible within a process and can affect child processes.

Common attack patterns include:

- Injecting special characters that affect shell interpretation
- Setting environment variables to bypass security controls
- Overriding sensitive configuration with attacker-controlled values
- Manipulating path-related environment variables to cause unsafe program behavior
- Using environment variables to communicate attack payloads between processes

## Non-compliant Code Example

```java
service / on new http:Listener(8080) {
    resource function get configPath(http:Request req) {
        string configPath = req.getQueryParamValue("path") ?: "";
        
        os:Error? err = os:setEnv("CONFIG_PATH", configPath);
    }
}
```

In this example, the application accepts a path from a query parameter and directly sets it as an environment variable without any validation. An attacker could provide malicious paths or inject special characters that might be interpreted by the shell or other processes that read this environment variable.

```java
service / on new http:Listener(8080) {
    resource function get runCommand(http:Request req) returns string|error {
        string commandArg = req.getQueryParamValue("arg") ?: "";
        string envValue = req.getQueryParamValue("env") ?: "";
        
        os:Process|os:Error result = os:exec(
            {value: "process-data", arguments: [commandArg]},
            USER_CONFIG = envValue
        );
    }
}
```

In this example, the application directly uses untrusted user input both as a command argument and an environment variable value without any validation or sanitization. This could lead to command injection or environment variable manipulation attacks.

## Compliant Code

```java
service / on new http:Listener(8080) {
    resource function get configPath(http:Request req) returns string|error {
        string configPath = req.getQueryParamValue("path") ?: "";
        
        if regex:matches(configPath, "^[a-zA-Z0-9]*$") {
            os:Error? err = os:setEnv("CONFIG_PATH", configPath);
            
            if err is os:Error {
                return error("Failed to set environment variable");
            }
            return "Environment variable set successfully";
        } else {
            return error("Invalid input: Only alphanumeric characters are allowed");
        }
    }
}
```

This approach implements proper input validation by ensuring that only alphanumeric characters are allowed in the environment variable value. It also includes appropriate error handling to manage any issues that occur during the environment variable setting process. By restricting the input to a safe character set, the code prevents injection attacks and environment variable manipulation.