## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | I/O function calls should not be vulnerable to path injection attacks |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| **Mapped CWEs** | [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)<br>[CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)<br>[CWE-35: Path Traversal: '.../...//'](https://cwe.mitre.org/data/definitions/35.html) |

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
    string filePath = "/path/to/target/directory/" + filename;

    check file:remove(filePath);
}
```

In this example, the application directly concatenates user input to form a file path without any validation or sanitization. An attacker could provide a filename like "../../../etc/passwd" to delete critical system files or access sensitive data outside the resources directory.

## Compliant Code

```java
public function main(string filename) returns error? {
    string targetDir = check file:getAbsolutePath("/path/to/target/directory/");

    string canonicalPath = check file:joinPath(targetDir, filename);

    if (!canonicalPath.startsWith(targetDir)) {
        io:println("Path traversal attempt detected");
        return error("Security violation: Attempted to access file outside allowed directory");
    }

    check file:remove(canonicalPath);
}
```

This approach resolves both the base directory and the requested file path to their canonical (absolute) forms, then verifies that the resulting path is still within the allowed directory. This approach handles complex traversal attempts by using the file system's own path resolution capabilities rather than trying to detect all possible traversal patterns.
