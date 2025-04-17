## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | JSON operations should not be vulnerable to injection attacks |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [A03:2021 – Injections](https://owasp.org/Top10/A03_2021-Injection/) |
| **Mapped CWEs** | [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)<br>[CWE-76: Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html) |

## Description

JSON injection occurs when an application dynamically creates JSON strings from user-controllable input without proper validation or escaping. When string interpolation or concatenation is used to build JSON strings, attackers can inject malicious payloads that manipulate the structure of the resulting JSON object.

This vulnerability can lead to:

- Schema poisoning where attackers modify the JSON structure
- Data manipulation by adding, modifying, or removing JSON properties
- Authorization bypass by injecting privileged attributes
- Potential server-side code execution if the JSON is later used in unsafe operations
- Client-side attacks if the manipulated JSON is returned to browsers

Common attack patterns include:

- Injecting quotation marks and commas to break JSON syntax
- Adding property-value pairs to gain unauthorized privileges
- Nesting additional objects or arrays within existing structures
- Injecting control characters to manipulate JSON parsing

For example, consider an application that accepts a username and description from a user. If an attacker provides the following payload:

```json
{
  "username": "attacker\", \"isAdmin\":true, \"privileges\":\"full",
  "description": "normal description"
}
```

When improperly processed through string interpolation, this could result in a JSON string like:

```json
{
    "user": "attacker",
    "isAdmin":true,
    "privileges":"full",
    "description": "normal description"
}
```

This injection could bypass authorization checks by adding unintended properties like `isAdmin` to the user object.

## Non-compliant Code

```java
service / on new http:Listener(8080) {
    resource function post createUser(@http:Payload record {|string username; string description;|} payload) returns json|error {
        string jsonString = string `{"user": "${payload.username}", "description": "${payload.description}"}`;

        json userData = check jsonString.fromJsonString();

        return userData;
    }
}
```

In this non-compliant example, the application constructs a JSON string using string interpolation with user-supplied input. This approach is vulnerable to JSON injection attacks because special characters in the input can break out of the intended JSON structure, potentially allowing attackers to insert arbitrary JSON properties.

## Compliant Code

```java
service / on new http:Listener(8080) {
    resource function post createUser(@http:Payload record {|string username; string description;|} payload) returns json|error {
        json userData = {
            "user": payload.username,
            "description": payload.description
        };

        return userData;
    }
}
```

This compliant approach uses Ballerina's native JSON handling capabilities to create a JSON object directly from variables rather than building a JSON string through concatenation or interpolation. By using the language's type system and JSON structure construction, the special characters in user input are automatically escaped properly, preventing injection attacks while maintaining the intended JSON structure.
