## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | Server-side requests should not be vulnerable to traversing attacks |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)<br>[Broken Access Control](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) |
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
        // Create a client with the base URL
        http:Client userClient = check new("http://example.com");
        
        // Make a request with properly constructed URL path
        json response = check userClient->get("/api/user/" + id);
        
        // Return the response as a string
        return response.toJsonString();
    }
}
```

In this example, the application directly concatenates user input to form a URL path without any validation or encoding. An attacker could provide an ID value containing URL control characters or sequences like "/../" to potentially access unintended resources or manipulate the request structure.

## Compliant Code

```java
service / on new http:Listener(8080) {
    resource function get user(string id) returns string|error {
        // Encode the path parameter to prevent URL injection
        string encodedId = check url:encode(id, "UTF-8");
        
        // Create a client with the base URL
        http:Client userClient = check new("http://example.com");
        
        // Make a request with properly constructed URL path
        json response = check userClient->get("/api/user/" + encodedId);
        
        // Return the response as a string
        return response.toJsonString();
    }
}
```

This approach uses proper URL encoding for the user-supplied parameter, ensuring that special characters in the input cannot manipulate the URL structure or introduce unintended path components.

## Best Practices

1. Always encode user inputs used in URL paths using appropriate URL encoding.
2. Implement input validation with allowlists rather than denylists.
3. Configure redirect policies to only allow trusted domains.
4. Implement network-level controls to restrict outgoing connections.
5. Use URL parsers to validate URL structure before making requests.
6. Consider implementing a proxy service for external requests that applies additional security checks.
7. In cloud environments, use appropriate IAM controls and network security groups.
8. Avoid exposing error details that could help attackers refine their SSRF attempts.
