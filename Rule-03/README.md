## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | Accessing files should not lead to filesystem oracle attacks |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)<br>[A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| **Mapped CWEs** | [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation<br>[CWE-22](https://cwe.mitre.org/data/definitions/22.html): Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |

## Description

Filesystem oracle attacks occur when applications reveal information about file existence, file attributes, or similar filesystem metadata without proper authorization. These attacks allow attackers to enumerate files and directories on the system, even if they cannot directly read the file contents.

When applications accept user input to check if files exist or to access file metadata, and return different responses based on the results, they can inadvertently create an information oracle that attackers can exploit to:

- Enumerate sensitive files on the system
- Map the directory structure
- Determine whether specific configuration or system files exist
- Perform timing attacks to infer information about the filesystem
- Gather intelligence for further attacks

These attacks are particularly concerning because they often bypass access controls that protect file contents but not metadata queries.

Common attack patterns include:
- Testing existence of known configuration files
- Brute-forcing filenames to map directory structures 
- Using timing differences to determine if files exist
- Leveraging error messages that disclose file information
- Using path traversal techniques to probe outside allowed directories

## Non-compliant Code Example

```java
public function main(string filename) returns error? {
    string filePath = "/path/to/target/directory/" + filename;

    boolean fileExists = check file:test(canonicalPath, file:EXISTS);

    if (!fileExists) {
        return error("File does not exist in the target directory");
    }
}
```

In this example, the application accepts a filename parameter from user input, directly concatenates it to construct a file path, and then checks if the file exists. This creates two vulnerabilities:

1. Path traversal - An attacker could provide a filename containing "../" sequences to access files outside the intended directory.
2. Filesystem oracle - The different responses for existing vs. non-existing files allow an attacker to enumerate files on the system.


## Compliant Code

```java
public function main(string filename) returns error? {
    string targetDir = check file:getAbsolutePath("/path/to/target/directory/");

    string canonicalPath = check file:joinPath(targetDir, filename);

    if (!canonicalPath.startsWith(targetDir)) {
        return error("Entry is outside of the target directory");
    } 

    boolean fileExists = check file:test(canonicalPath, file:EXISTS);

    if (!fileExists) {
        return error("File does not exist in the target directory");
    }
}
```

This approach validates that the requested file is within the intended directory, preventing path traversal attacks, and it prevents testing the existence of a file outside the intended directory.