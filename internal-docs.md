# DVWA - Exposed Secrets Vulnerability Report

## Executive Summary
This document catalogs all exposed secrets, credentials, and hardcoded sensitive information found in the DVWA (Damn Vulnerable Web Application) project. This repository is intentionally vulnerable for educational purposes, but the exposed secrets make it an excellent case study for security scanning tools.

---

## 1. Database Credentials

### Location: [config/config.inc.php.dist](config/config.inc.php.dist)
**Severity:** CRITICAL

| Secret Type | Value | Details |
|---|---|---|
| Database Server | `127.0.0.1` | Default MySQL/MariaDB host |
| Database Port | `3306` | Standard MySQL port |
| Database User | `dvwa` | Default database username |
| Database Password | `p@ssw0rd` | Weak default password |
| Database Name | `dvwa` | Database name |

**Code Reference:**
```php
$_DVWA[ 'db_server' ]   = getenv('DB_SERVER') ?: '127.0.0.1';
$_DVWA[ 'db_port']      = getenv('DB_PORT') ?: '3306';
$_DVWA[ 'db_user' ]     = getenv('DB_USER') ?: 'dvwa';
$_DVWA[ 'db_password' ] = getenv('DB_PASSWORD') ?: 'p@ssw0rd';
$_DVWA[ 'db_database' ] = getenv('DB_DATABASE') ?: 'dvwa';
```

---

## 2. Docker Compose Secrets

### Location: [compose.yml](compose.yml)
**Severity:** CRITICAL

| Secret Type | Value | Details |
|---|---|---|
| MySQL Root Password | `dvwa` | Root user password |
| MySQL Database | `dvwa` | Database name |
| MySQL User | `dvwa` | Service user |
| MySQL User Password | `p@ssw0rd` | Service user password |

**Code Reference:**
```yaml
db:
  image: docker.io/library/mariadb:10
  environment:
    - MYSQL_ROOT_PASSWORD=dvwa
    - MYSQL_DATABASE=dvwa
    - MYSQL_USER=dvwa
    - MYSQL_PASSWORD=p@ssw0rd
```

---

## 3. API Authentication Credentials

### Location: [vulnerabilities/api/src/LoginController.php](vulnerabilities/api/src/LoginController.php) (Lines 48-70)
**Severity:** HIGH

| Secret Type | Value | Details |
|---|---|---|
| API Username | `mrbennett` | Test user for JSON login |
| API Password | `becareful` | Associated weak password |
| OAuth2 Client ID | `1471.dvwa.digi.ninja` | Application identifier |
| OAuth2 Client Secret | `ABigLongSecret` | Application authentication secret |

**Code Reference:**
```php
private function loginJSON() {
    if ($username == "mrbennett" && $password == "becareful") {
        $response['status_code_header'] = 'HTTP/1.1 200 OK';
        $response['body'] = json_encode (array ("token" => Login::create_token()));
    }
}

private function login() {
    if ($client_id == "1471.dvwa.digi.ninja" && $client_secret == "ABigLongSecret") {
        // Authentication logic
    }
}
```

---

## 4. API Token Secrets

### Location: [vulnerabilities/api/src/Login.php](vulnerabilities/api/src/Login.php)
**Severity:** HIGH

| Secret Type | Value | Details |
|---|---|---|
| Access Token Secret | `12345` | Token validation secret (weak) |
| Refresh Token Secret | `98765` | Refresh token validation secret (weak) |
| Access Token Lifetime | `180` | Seconds (3 minutes) |
| Refresh Token Lifetime | `240` | Seconds (4 minutes) |

**Code Reference:**
```php
class Login {
    private const ACCESS_TOKEN_SECRET = "12345";
    private const REFRESH_TOKEN_SECRET = "98765";
    private const ACCESS_TOKEN_LIFE = 180;
    private const REFRESH_TOKEN_LIFE = 240;
}
```

---

## 5. API Encryption Keys

### Location: [vulnerabilities/api/src/Token.php](vulnerabilities/api/src/Token.php)
**Severity:** HIGH

| Secret Type | Value | Cipher | Details |
|---|---|---|---|
| Encryption Key | `Paintbrush` | AES-128-GCM | Used for token encryption |
| Encryption Algorithm | `aes-128-gcm` | AES-128-GCM | Authenticated encryption |

**Code Reference:**
```php
class Token {
    private const ENCRYPTION_CIPHER = "aes-128-gcm";
    private const ENCRYPTION_KEY = "Paintbrush";
}
```

---

## 6. Cryptography Lab Encryption Keys

### Location: [vulnerabilities/cryptography/source/token_library_high.php](vulnerabilities/cryptography/source/token_library_high.php)
**Severity:** MEDIUM

| Secret Type | Value | Cipher | Details |
|---|---|---|---|
| Encryption Key | `rainbowclimbinghigh` | AES-128-CBC | Token encryption key |
| Static IV | `1234567812345678` | AES-128-CBC | Static initialization vector (weak) |
| Algorithm | `aes-128-cbc` | AES-128-CBC | Block cipher mode |

**Code Reference:**
```php
define ("KEY", "rainbowclimbinghigh");
define ("ALGO", "aes-128-cbc");
define ("IV", "1234567812345678");
```

### Location: [vulnerabilities/cryptography/source/medium.php](vulnerabilities/cryptography/source/medium.php)
**Severity:** MEDIUM

| Secret Type | Value | Cipher | Details |
|---|---|---|---|
| Encryption Key | `ik ben een aardbei` | AES-128-ECB | Dutch phrase meaning "I am a strawberry" |
| Algorithm | `aes-128-ecb` | AES-128-ECB | Weak ECB mode (deterministic) |

**Code Reference:**
```php
$key = "ik ben een aardbei";
function decrypt ($ciphertext, $key) {
    $e = openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING);
}
```

---

## 7. Default Application Credentials

### Location: [README.md](README.md) and related documentation
**Severity:** MEDIUM

| Secret Type | Value | Details |
|---|---|---|
| Default Username | `admin` | Standard login user |
| Default Password | `password` | Weak default password |
| Login URL | `http://127.0.0.1/login.php` | Application entry point |

**Documentation Reference:**
```markdown
### Default Credentials

**Default username = `admin`**
**Default password = `password`**

_...can easily be brute forced ;)_
```

---

## 8. ReCAPTCHA Configuration

### Location: [config/config.inc.php.dist](config/config.inc.php.dist)
**Severity:** LOW (when populated)

| Secret Type | Value | Details |
|---|---|---|
| ReCAPTCHA Public Key | (Empty by default) | Google ReCAPTCHA v2 public key |
| ReCAPTCHA Private Key | (Empty by default) | Google ReCAPTCHA v2 private key |

**Code Reference:**
```php
$_DVWA[ 'recaptcha_public_key' ]  = getenv('RECAPTCHA_PUBLIC_KEY') ?: '';
$_DVWA[ 'recaptcha_private_key' ] = getenv('RECAPTCHA_PRIVATE_KEY') ?: '';
```

**Note:** Users must generate their own keys from https://www.google.com/recaptcha/admin/create

---

## Vulnerability Analysis

### Common Issues Identified

1. **Hardcoded Credentials in Source Code**
   - Database credentials in configuration files
   - API authentication tokens in source code
   - Encryption keys as class constants

2. **Weak Secrets**
   - Simple, short passwords (`p@ssw0rd`, `dvwa`, `password`)
   - Numeric token secrets (`12345`, `98765`)
   - Dictionary words for encryption keys (`Paintbrush`, `rainbowclimbinghigh`)

3. **Cryptographic Weaknesses**
   - Use of ECB mode (deterministic encryption)
   - Static initialization vectors (IVs)
   - Weak key derivation

4. **Exposure in Repository**
   - Credentials in version control (.dist files that become production configs)
   - Secrets in Docker Compose files
   - Sensitive data in example/documentation files

5. **Authentication Weaknesses**
   - Hardcoded user credentials in API
   - OAuth2 credentials exposed in source
   - Client secrets embedded in code

---

## Security Recommendations for Production Systems

1. **Use Environment Variables**
   - Store all secrets in environment variables (`.env` files, not in repo)
   - Use secret management systems (AWS Secrets Manager, HashiCorp Vault, etc.)

2. **Implement Secrets Scanning**
   - Use tools like:
     - `git-secrets`
     - `TruffleHog`
     - `detect-secrets`
     - `OWASP Secret Scanning`
   - Pre-commit hooks to prevent secret commits

3. **Strong Cryptography Practices**
   - Use random IVs for each encryption operation
   - Avoid ECB mode; use CBC, CTR, or GCM modes
   - Generate cryptographic keys from proper sources
   - Use standard libraries for encryption

4. **Credential Management**
   - Never commit secrets to version control
   - Rotate secrets regularly
   - Use strong passwords (min 16+ characters)
   - Implement MFA for sensitive systems

5. **Code Review**
   - Peer review code for hardcoded secrets
   - Automated scanning in CI/CD pipelines
   - Regular security audits

---

## Testing Methodology for Security Tools

This DVWA repository serves as an excellent test case for:

- **Secret Detection Tools:** Verify tool can identify all hardcoded secrets
- **SAST Scanners:** Test static analysis for credential exposure
- **Dependency Scanning:** Test against known vulnerable patterns
- **Configuration Analysis:** Verify detection of weak configurations
- **Cryptographic Analysis:** Detect weak cipher usage

### Recommended Tool Validations

- [ ] Detect all database credentials
- [ ] Identify hardcoded API keys and tokens
- [ ] Flag weak encryption keys and algorithms
- [ ] Detect ECB mode usage
- [ ] Identify static IVs
- [ ] Report weak password policies
- [ ] Flag OAuth2 credentials exposure

---

## References

- [OWASP: Sensitive Data Exposure](https://owasp.org/www-project-top-ten/)
- [CWE-798: Use of Hard-Coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-321: Use of Hard-Coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [NIST Guidelines on Cryptography](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [Git Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)

---

**Document Version:** 1.0  
**Last Updated:** February 4, 2026  
**Status:** Complete vulnerability inventory of DVWA exposed secrets
