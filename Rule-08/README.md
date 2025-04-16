## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | Encryption algorithms should be used with secure mode and padding scheme |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| **Mapped CWEs** | [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)<br>[CWE-780: Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html) |

## Description

Encryption algorithms are essential for protecting sensitive information and ensuring secure communications. When implementing encryption, it's critical to select not only strong algorithms but also secure modes of operation and padding schemes. Using weak or outdated encryption modes can compromise the security of otherwise strong algorithms.

The security risks of using weak encryption modes include:

- Data confidentiality breaches where encrypted content becomes readable
- Modification of encrypted data without detection
- Pattern recognition in encrypted data that reveals information about the plaintext
- Replay attacks where valid encrypted data is reused maliciously
- Known-plaintext attacks that can reveal encryption keys

Common vulnerable patterns include:

- Using ECB (Electronic Codebook) mode which doesn't hide data patterns
- Implementing CBC (Cipher Block Chaining) without integrity checks
- Using RSA encryption without proper padding schemes
- Relying on outdated padding methods like PKCS1v1.5
- Using stream ciphers with insufficient initialization vectors

Using weak encryption algorithms, modes, or padding schemes can lead to:

1. **Theft of sensitive data**: Encrypted messages might contain sensitive information that shouldn't be exposed to third parties. Weak algorithms significantly increase the possibility of an attacker recovering the plaintext.

2. **Additional attack surface**: By modifying the plaintext of encrypted messages, attackers might trigger other vulnerabilities in the code. Since encrypted values are often considered trusted, this can lead to unexpected security breaches.

3. **Pattern analysis**: In modes like ECB, patterns in the original data remain visible in the encrypted output, potentially revealing information about the plaintext without fully decrypting it.

4. **Integrity violations**: Without authenticated encryption, attackers may be able to manipulate encrypted data without detection, potentially leading to unintended system behavior.

## Non-compliant Code

```java
byte[] cipherText = check crypto:encryptAesEcb(data, key);
```

For AES, the weakest mode is ECB (Electronic Codebook). Repeated blocks of data are encrypted to the same value, making them easy to identify and reducing the difficulty of recovering the original cleartext.

```java
byte[] cipherText = check crypto:encryptAesCbc(data, key, initialVector);
```

Unauthenticated modes such as CBC (Cipher Block Chaining) may be used but are prone to attacks that manipulate the ciphertext (like padding oracle attacks). They must be used with caution and additional integrity checks.

## Compliant Code

```java
byte[] cipherText = check crypto:encryptAesGcm(data, key, initialVector);
```
AES-GCM (Galois/Counter Mode) provides authenticated encryption, ensuring both confidentiality and integrity of the encrypted data.