## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | I/O function calls should not be vulnerable to path injection attacks |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [Broken Access Control](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) |
| **Mapped CWEs** | [CWE-22](https://cwe.mitre.org/data/definitions/22.html): Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')<br>[CWE-23](https://cwe.mitre.org/data/definitions/23.html): Relative Path Traversal<br>[CWE-35](https://cwe.mitre.org/data/definitions/35.html): Path Traversal: '.../...//' |

## Description

Path traversal (also known as directory traversal) is a vulnerability that allows attackers to access files and directories outside of the intended directory by manipulating file paths. When applications accept user input to construct file paths without proper validation or sanitization, attackers can inject sequences like "../" to navigate up directory levels and access sensitive files elsewhere on the system.

Common attack patterns include:
- Using "../" sequences (e.g., "../../../etc/passwd")
- Using encoded variants ("%2e%2e%2f")
- Using absolute paths ("/etc/passwd")
- Using nested traversals that survive simple sanitization ("..././../..")

The impact of successful path traversal can include unauthorized access to sensitive files, configuration data, or even system files, potentially leading to information disclosure, privilege escalation, or remote code execution.

## Non-compliant Code

```java
public function main(string filename) returns error? {
    string filePath = "./resources/" + filename;

    check file:remove(filePath);
}
```

In this example, the application directly concatenates user input to form a file path without any validation or sanitization. An attacker could provide a filename like "../../../etc/passwd" to delete critical system files or access sensitive data outside the resources directory.

## Compliant Code

```java
public function main(string filename) returns error? {
    // Define base resource directory as an absolute path
    string resourceDir = check file:getAbsolutePath("./resources");

    // Construct canonical path
    string canonicalPath = check file:joinPath(resourceDir, filename);

    // Verify the canonicalized path is still within the resource directory
    if (!canonicalPath.startsWith(resourceDir)) {
        io:println("Path traversal attempt detected");
        return error("Security violation: Attempted to access file outside allowed directory");
    }

    check file:remove(canonicalPath);
}
```

This approach resolves both the base directory and the requested file path to their canonical (absolute) forms, then verifies that the resulting path is still within the allowed directory. This approach handles complex traversal attempts by using the file system's own path resolution capabilities rather than trying to detect all possible traversal patterns.

## Best Practices

1. Never directly incorporate user input into file paths without validation.
2. Use absolute paths with a whitelist approach whenever possible.
3. Implement proper input validation with strong regular expressions.
4. Use canonical path resolution and verify the final path is within allowed boundaries.
5. Apply the principle of least privilege for file system operations.
6. Consider using file access abstractions rather than direct file paths.