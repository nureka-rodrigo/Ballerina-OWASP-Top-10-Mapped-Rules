## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | Applications should not create session cookies from untrusted input |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [A03:2021 – Injections](https://owasp.org/Top10/A03_2021-Injection/) |
| **Mapped CWEs** | [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)<br>[CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html) |

## Description

Session fixation is an attack that allows an attacker to hijack a valid user session by tricking the user into using a session identifier known to the attacker. This occurs when applications allow users or external sources to specify the session identifier rather than generating secure random identifiers internally.

This vulnerability can lead to:

- Account hijacking where attackers take over legitimate user sessions
- Unauthorized access to sensitive user data and functionality
- Bypass of authentication mechanisms
- Identity theft through stolen session credentials
- Bypassing multi-factor authentication after initial login

Common attack patterns include:

- Providing a predetermined session ID as a query parameter
- Sending session IDs through request headers
- Setting session identifiers via manipulated cookies
- Exploiting applications that don't regenerate session IDs after authentication

For example, in a session fixation attack:

1. An attacker obtains a valid session ID from the application
2. The attacker tricks a victim into using that session ID (via a crafted link, XSS, etc.)
3. The victim logs in with their credentials while using the attacker's session ID
4. The attacker now has access to the victim's authenticated session

## Non-compliant Code

```java
service / on new http:Listener(8080) {
    resource function get createSession(http:Request req) returns http:Response|error? {
        string sessionId = req.getQueryParamValue("sessionId") ?: "";

        http:Response res = new;
        http:Cookie cookie = new ("SESSIONID", sessionId, path = "/");

        res.addCookie(cookie);
        res.setTextPayload("Session created");

        return res;
    }
}
```

In this non-compliant example, the application accepts a session ID directly from a query parameter and uses it to create a session cookie. This approach is vulnerable to session fixation attacks because attackers can craft a session ID, provide it to victims, and then hijack their authenticated sessions.

## Compliant Code

```java
service / on new http:Listener(8080) {
    resource function get createSession(http:Request req) returns http:Response|error? {
        string sessionId = uuid:createType1AsString();

        http:Response res = new;
        http:Cookie cookie = new ("SESSIONID", sessionId, path = "/");

        res.addCookie(cookie);
        res.setTextPayload("Session created");

        return res;
    }
}
```

This compliant approach generates a secure random session identifier using the UUID module instead of accepting user input. By generating session IDs internally, the application prevents attackers from knowing session identifiers in advance, which mitigates session fixation attacks.

## Reference

[SonarQube Rule: Applications should not create session cookies from untrusted input](https://rules.sonarsource.com/java/RSPEC-6287/)
