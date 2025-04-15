## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | Server-side requests should not be vulnerable to traversing attacks |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)<br>[Broken Access Control](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) |
| **Mapped CWEs** | [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation<br>[CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF) |

## Non-compliant Code Example

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

## Compliant Code Example

### Encode URL Parameters

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
