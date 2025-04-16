## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | Server hostnames should be verified during SSL/TLS connections |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)<br>[A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)<br>[A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| **Mapped CWEs** | [CWE-297: Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html) |

## Description

When establishing SSL/TLS connections, it's critical to verify that the server being connected to is the intended one by validating its hostname against the certificate it presents. Hostname verification is a crucial part of the SSL/TLS handshake that prevents man-in-the-middle attacks.

Failing to verify server hostnames during SSL/TLS connections can lead to several security risks:

- Man-in-the-middle attacks where attackers intercept communications
- Connection to malicious servers impersonating legitimate ones
- Data disclosure to unintended recipients
- Credential theft through spoofed services
- Loss of confidentiality and integrity of transmitted data

Common vulnerable patterns include:

- Disabling hostname verification in SSL/TLS configurations
- Using custom trust managers that bypass hostname verification
- Accepting all certificates without validation
- Implementing insecure verification callbacks that always return true
- Setting security configurations to their minimal or default values

## Non-compliant Code

```java
public function main() {
    email:SmtpClient smtpClient = check new ("smtp.email.com", "sender@email.com", "pass123");
}
```

In this non-compliant example, an SMTP client is created without explicitly setting the security mode. Without explicit security configuration, the connection might not properly validate the server's hostname against its certificate.

## Compliant Code

```java
public function main() {
    email:Security security = email:SSL;

    email:SmtpConfiguration smtpConfig = {
        port: 465,
        security
    };

    email:SmtpClient smtpClient = check new ("smtp.email.com", "sender@email.com", "pass123", smtpConfig);
}
```

This compliant code explicitly sets the security mode to SSL, ensuring that not only is the connection encrypted, but also that the server's hostname is properly verified against its certificate. By explicitly configuring the security settings, the application ensures that it connects only to the intended server, protecting against potential man-in-the-middle attacks.