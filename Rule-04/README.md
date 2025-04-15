## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | Credentials should not be hard-coded |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| **Mapped CWEs** | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)<br>[CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html) |

## Description

Hard-coding credentials such as passwords, API keys, and database connection strings directly in source code is a serious security vulnerability. These credentials can be exposed through:

- Source code repositories (public or private)
- Application binaries through reverse engineering
- Source code leaks or unauthorized access
- Debug logs or stack traces that reveal portions of code

When credentials are hard-coded, they are difficult to rotate or change without recompiling the application. Additionally, all instances of an application typically share the same credentials, making them high-value targets for attackers.

The risks of hard-coded credentials include:

- Unauthorized access to systems and data
- Inability to follow the principle of least privilege
- Credential exposure in case of source code compromise
- Difficulty in tracking who has access to the credentials
- Challenges in implementing proper credential rotation policies

## Non-compliant Code Example

```java
service / on new http:Listener(8080) {
    private final mysql:Client db;

    function init() returns error? {
        self.db = check new ("localhost", "root", "Test@123", "MUSIC_STORE", 3306);
    }

    // Interact with the database
}
```

In this example, the database credentials are hard-coded directly in the service initialization. The username "root" and password "Test@123" are exposed in the source code. If this code is committed to a repository, these credentials would be visible to anyone with access to the repository, creating significant security risks.

## Compliant Code


```java
configurable string dbHost = os:getEnv("DB_HOST") ?: "localhost";
configurable string dbUser = os:getEnv("DB_USER");
configurable string dbPassword = os:getEnv("DB_PASSWORD");
configurable string dbName = os:getEnv("DB_NAME") ?: "MUSIC_STORE";
configurable int dbPort = check int:fromString(os:getEnv("DB_PORT") ?: "3306");

service / on new http:Listener(8080) {
    private final mysql:Client db;

    function init() returns error? {
        self.db = check new (dbHost, dbUser, dbPassword, dbName, dbPort);
    }

    // Interact with the database
}
```

This compliant approach uses Ballerina's configurable variables and environment variables to retrieve sensitive credentials at runtime rather than hard-coding them. The credentials can be securely configured during deployment without modifying code, and they aren't stored in source control.