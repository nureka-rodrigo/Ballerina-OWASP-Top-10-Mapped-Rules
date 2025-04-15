## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | Server-side requests should not be vulnerable to traversing attacks |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [A10:2021 – Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)<br>[A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| **Mapped CWEs** | [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation<br>[CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF) |

## Description

Server-Side Request Forgery (SSRF) is a vulnerability that allows attackers to induce the server-side application to make requests to an unintended location. When applications accept user input that influences server-side HTTP requests without proper validation or sanitization, attackers can manipulate these requests to:

- Access internal services behind firewalls
- Scan internal networks
- Interact with metadata services in cloud environments
- Perform denial-of-service attacks
- Leverage server privileges to access restricted resources

SSRF attacks are particularly dangerous in cloud environments where metadata services can expose sensitive information such as credentials and configuration data.

Common attack patterns include:
- Manipulating URL parameters to reach internal IPs (e.g., 127.0.0.1, 192.168.x.x)
- Using alternate encoding schemes to bypass filters (e.g., decimal IPs, hex encoding)
- Abusing URL redirects
- Using DNS rebinding to bypass hostname-based restrictions
- Using non-HTTP URL schemes like file://, gopher://, or dict://

## Non-compliant Code

```java
service / on new http:Listener(8080) {
    resource function get user(string id) returns string|error { 
        http:Client userClient = check new("http://example.com");
        
        json response = check userClient->get("/api/user/" + id);
        
        return response.toJsonString();
    }
}
```

In this example, the application directly concatenates user input to form a URL path without any validation or encoding. An attacker could provide an ID value containing URL control characters or sequences like "/../" to potentially access unintended resources or manipulate the request structure.

## Compliant Code

```java
service / on new http:Listener(8080) {
    resource function get user(string id) returns string|error {
        string encodedId = check url:encode(id, "UTF-8");
        
        http:Client userClient = check new("http://example.com");
        
        json response = check userClient->get("/api/user/" + encodedId);
        
        return response.toJsonString();
    }
}
```

This approach uses proper URL encoding for the user-supplied parameter, ensuring that special characters in the input cannot manipulate the URL structure or introduce unintended path components.
