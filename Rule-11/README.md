## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | Avoid revealing sensitive error information |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [A04:2021 – Insecure Design](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| **Mapped CWEs** | [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) |

## Description

When applications expose detailed error messages and stack traces to users, they inadvertently reveal sensitive information about the system's inner workings. These technical details can provide attackers with valuable insights into:

- Programming languages and frameworks used
- Database structures and query patterns
- File paths and system architecture
- Internal application logic and control flow
- Potential attack vectors and entry points

Revealing this information makes it easier for attackers to identify and exploit vulnerabilities within the application.

Common problematic practices include:

- Displaying database error messages directly to users
- Exposing full stack traces in web responses
- Including detailed system configuration information in errors
- Revealing internal file paths or sensitive variable values
- Leaking authentication or authorization failure details

## Non-compliant Code

```java
service / on new http:Listener(8080) {
    resource function get readFile(string fileName) returns string? {
        var result = io:fileReadLinesAsStream("path/to/your/directory/" + fileName);

        if (result is io:Error) {
            log:printError("Error reading file: ", result);
            return "Error: " + result.message();
        }

        return "File read successfully!";
    }
}
```

In this non-compliant example, the application returns the actual error message to the client. This could reveal sensitive information like file paths, access permissions, or system configuration details that an attacker could leverage to plan further attacks.

## Compliant Code

```java
service / on new http:Listener(8080) {
    resource function get readFile(string fileName) returns string? {
        var result = io:fileReadLinesAsStream("path/to/your/directory/" + fileName);

        if (result is io:Error) {
            log:printError("Error reading file: ", result);
            return "An error occurred while reading the file.";
        }

        return "File read successfully!";
    }
}
```

The compliant code properly handles errors by returning only a generic error message to the user that doesn't reveal sensitive system details. This approach ensures users receive appropriate feedback while preventing the exposure of information that could aid malicious actors.
