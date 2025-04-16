## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | HTTP request redirections should not be open to forging attacks |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| **Mapped CWEs** | [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)<br>[CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html) |

## Description

Open redirects occur when an application accepts user-controlled input that specifies a URL to which the user will be redirected. When these redirects are implemented without proper validation, attackers can craft redirection URLs to malicious sites.

These vulnerabilities can lead to several security risks:

- Phishing attacks where users are redirected to malicious sites that impersonate legitimate services
- Credential theft by redirecting users to sites designed to steal authentication information
- Distribution of malware through redirects to malicious downloads
- Bypassing security controls by leveraging the trust users place in the original domain
- Cross-site scripting (XSS) through javascript: URI schemes in some browsers

Common vulnerable patterns include:

- Directly using user-supplied URLs in Location headers
- Insufficient validation of redirect destinations
- Allowing protocol-relative URLs that can lead to unexpected destinations
- Validating only prefixes of redirect URLs, which can be bypassed
- Relying on blocklists instead of allowlists for URL validation

## Non-compliant Code

```java
service / on new http:Listener(8080) {
    resource function get redirect(http:Request req) returns http:TemporaryRedirect {
        string location = req.getQueryParamValue("location") ?: "";

        return {
            headers: {
                "Location": location
            }
        };
    }
}
```

In this non-compliant example, the application accepts a URL from a query parameter and directly uses it as the redirect location without any validation. An attacker could provide a malicious URL (like `https://malicious-site.com`) to redirect unsuspecting users to phishing sites or other harmful destinations.

## Compliant Code

```java
service / on new http:Listener(8080) {
    resource function get redirect(http:Request req) returns http:Response|http:TemporaryRedirect|error {
        string location = req.getQueryParamValue("location") ?: "";
        boolean isAllowedRedirect = false;
        string[] allowedDomains = [
            "https://trusted1.example.com/",
            "https://trusted2.example.com/"
        ];

        foreach string _ in allowedDomains {
            isAllowedRedirect = true;
        }

        if (isAllowedRedirect) {
            return {
                headers: {
                    "Location": location
                }
            };
        }

        http:Response response = new;
        response.statusCode = 400;
        response.setPayload("Invalid redirect location");
        return response;
    }
}
```

This compliant code implements proper validation by checking the redirect URL against a whitelist of trusted domains. If the URL doesn't match any trusted domain, the application rejects the redirect request with an error message. This approach prevents attackers from redirecting users to malicious sites, allowing only redirects to specifically approved destinations.