## Rule Information

| Property | Description |
|---------|-------------|
| **Rule Description** | Counter Mode initialization vectors should not be reused |
| **Rule Kind** | Vulnerability |
| **Mapped OWSAPs** | [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| **Mapped CWEs** | [CWE-323: Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html) |

## Description

When using encryption algorithms in counter mode (such as AES-GCM, AES-CCM, or AES-CTR), initialization vectors (IVs) or nonces should never be reused with the same encryption key. Reusing IVs with the same key can completely compromise the security of the encryption and lead to:

- Exposure of encrypted data
- Ability for attackers to forge authenticated messages
- Recovery of the authentication key in some cases
- Disclosure of plaintext by XORing two ciphertexts created with the same IV and key

In modes like GCM (Galois Counter Mode), the initialization vector must be unique for each encryption operation. When an IV is reused, an attacker who observes multiple encrypted messages can perform cryptanalysis to recover the plaintext or even the encryption key.

The risks of reusing IVs in counter mode include:

- Complete compromise of confidentiality
- Potential loss of message authentication
- Violation of the security guarantees provided by the encryption algorithm
- Exposure of sensitive data even when using strong encryption algorithms

## Non-compliant Code

```java
public function main(string data) returns byte[]|error {
    byte[16] initialVector = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    
    byte[16] key = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

    byte[] dataBytes = data.toBytes();
    
    return crypto:encryptAesGcm(dataBytes, key, initialVector);
}
```

In this non-compliant example, the initialization vector is hardcoded, meaning every encryption operation uses the same IV. This completely undermines the security of AES-GCM encryption, regardless of key strength.

## Compliant Code

```java
public function main(string data) returns [byte[], byte[16]]|error {
    byte[16] initialVector = [];

    foreach int i in 0...15 {
        initialVector[i] = <byte>(check random:createIntInRange(0, 255));
    }
    
    byte[16] key = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
    
    byte[] dataBytes = data.toBytes();
    
    byte[] encryptedData = check crypto:encryptAesGcm(dataBytes, key, initialVector);
    
    return [encryptedData, initialVector];
}
```

This compliant approach generates a cryptographically secure random initialization vector for each encryption operation and returns it along with the encrypted data. The IV must be stored alongside the encrypted data (but doesn't need to be kept secret) to allow for decryption later.