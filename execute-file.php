<?php
/**
 * PLEXALYZER VULNERABILITY TEST FILE
 * 
 * This file intentionally contains multiple types of security vulnerabilities
 * to test the detection capabilities of the Plexalyzer security scanner.
 * 
 * DO NOT USE IN PRODUCTION - FOR TESTING ONLY
 */

// ============================================================================
// 1. SQL INJECTION VULNERABILITIES
// ============================================================================

function test_sql_injection_basic() {
    // CWE-89: SQL Injection - Direct concatenation
    $user_id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = '" . $user_id . "';";
    // Attack: id=1' OR '1'='1
    mysqli_query($GLOBALS["db"], $query);
}

function test_sql_injection_post() {
    // CWE-89: SQL Injection via POST
    if (isset($_POST['username'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];
        $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password';";
        // Attack: username=admin'--
        $result = mysqli_query($GLOBALS["db"], $query);
    }
}

function test_sql_injection_cookie() {
    // CWE-89: SQL Injection via Cookie
    $user_pref = $_COOKIE['user_preference'];
    $query = "SELECT * FROM preferences WHERE user_id = " . $user_pref;
    mysqli_query($GLOBALS["db"], $query);
}

// ============================================================================
// 2. CROSS-SITE SCRIPTING (XSS) VULNERABILITIES
// ============================================================================

function test_xss_reflected() {
    // CWE-79: Cross-Site Scripting - Reflected
    $search = $_GET['search'];
    echo "<h1>Search results for: " . $search . "</h1>";
    // Attack: <script>alert('XSS')</script>
}

function test_xss_stored() {
    // CWE-79: Cross-Site Scripting - Stored
    if (isset($_POST['comment'])) {
        $comment = $_POST['comment'];
        // Store directly without sanitization
        $query = "INSERT INTO comments (content) VALUES ('$comment')";
        mysqli_query($GLOBALS["db"], $query);
    }
    
    // Later, display without escaping
    $result = mysqli_query($GLOBALS["db"], "SELECT * FROM comments");
    while ($row = mysqli_fetch_assoc($result)) {
        echo $row['content']; // Vulnerable!
    }
}

function test_xss_dom() {
    // CWE-79: DOM-based XSS
    $html = "<script>";
    $html .= "var userInput = '" . $_GET['user_data'] . "';";
    $html .= "document.body.innerHTML = userInput;";
    $html .= "</script>";
    echo $html;
}

// ============================================================================
// 3. HARDCODED CREDENTIALS & SECRETS
// ============================================================================

function test_hardcoded_secrets() {
    // CWE-798: Use of Hard-Coded Credentials
    
    // Database credentials
    $db_host = "localhost";
    $db_user = "admin";
    $db_password = "SuperSecretPassword123";
    $db_name = "production_db";
    
    // API Keys (FAKE - for testing only)
    $api_key = "api_key_test_12345678901234567890";
    $stripe_secret = "test_secret_key_abcdefghijklmnop";
    $aws_access_key = "AKIA_FAKE_EXAMPLE_12345678";
    $aws_secret_key = "wJalrXUtnFAKE_EXAMPLE_bPxRfiCYEXAMPLE";
    
    // OAuth tokens (FAKE - for testing only)
    $github_token = "ghp_fake_token_1234567890abcdefghij";
    $slack_webhook = "https://hooks.slack.com/services/TFAKE/BFAKE/XXXXXXXXXXXXXXXXXXXX";
    
    // Encryption keys
    $encryption_key = "my-secret-encryption-key-12345";
    $jwt_secret = "supersecretjwtsigningkey";
}

function test_hardcoded_oauth() {
    // OAuth2 credentials embedded (FAKE - for testing only)
    $client_id = "fake_client_id_1471_example";
    $client_secret = "fake_client_secret_longstring123";
    
    return [
        "client_id" => $client_id,
        "client_secret" => $client_secret
    ];
}

// ============================================================================
// 4. COMMAND INJECTION VULNERABILITIES
// ============================================================================

function test_command_injection() {
    // CWE-78: Improper Neutralization of Special Elements used in an OS Command
    
    $filename = $_GET['file'];
    $command = "cat /var/www/html/files/" . $filename;
    // Attack: file=../../etc/passwd
    system($command);
}

function test_command_injection_exec() {
    // CWE-78: Command Injection via exec()
    $user_input = $_POST['command'];
    exec("convert image.jpg -quality " . $user_input . " output.jpg");
    // Attack: command=; rm -rf /
}

function test_command_injection_shell() {
    // CWE-78: Command Injection via shell_exec()
    $zip_file = $_GET['zipfile'];
    $output = shell_exec("unzip " . $zip_file);
    // Attack: zipfile=test.zip; cat /etc/passwd
    echo $output;
}

// ============================================================================
// 5. PATH TRAVERSAL VULNERABILITIES
// ============================================================================

function test_path_traversal() {
    // CWE-22: Improper Limitation of a Pathname to a Restricted Directory
    
    $file = $_GET['file'];
    $content = file_get_contents("/var/www/uploads/" . $file);
    // Attack: file=../../etc/passwd
    echo $content;
}

function test_path_traversal_include() {
    // CWE-22: Path Traversal with include()
    $page = $_GET['page'];
    include("/var/www/pages/" . $page . ".php");
    // Attack: page=../../../etc/passwd%00
}

// ============================================================================
// 6. INSECURE DESERIALIZATION
// ============================================================================

function test_insecure_unserialize() {
    // CWE-502: Deserialization of Untrusted Data
    
    $user_data = $_GET['data'];
    $unserialized = unserialize($user_data);
    // Attack: PHP object injection via crafted serialized data
}

function test_insecure_json_decode() {
    // While JSON is safer, can still lead to issues
    $json_input = $_POST['json'];
    $data = json_decode($json_input, true);
    
    // If used in queries:
    $query = "SELECT * FROM users WHERE id = " . $data['user_id'];
    mysqli_query($GLOBALS["db"], $query);
}

// ============================================================================
// 7. WEAK CRYPTOGRAPHY
// ============================================================================

function test_weak_encryption() {
    // CWE-327: Use of a Broken or Risky Cryptographic Algorithm
    
    $plaintext = "sensitive_data";
    $key = "secretkey";
    
    // Using weak ECB mode
    $encrypted = openssl_encrypt($plaintext, 'aes-128-ecb', $key);
    
    // Using deprecated md5 for hashing passwords
    $password_hash = md5($plaintext);
    
    // Using rand() instead of random_bytes()
    $token = md5(rand());
}

function test_weak_random() {
    // CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator
    
    $session_token = rand(1, 999999);
    $csrf_token = uniqid();
    $api_key = md5(time());
}

// ============================================================================
// 8. INSECURE FILE UPLOAD
// ============================================================================

function test_insecure_upload() {
    // CWE-434: Unrestricted Upload of File with Dangerous Type
    
    if (isset($_FILES['upload'])) {
        $filename = $_FILES['upload']['name'];
        $tmp_file = $_FILES['upload']['tmp_name'];
        
        // No validation of file type
        move_uploaded_file($tmp_file, "/var/www/uploads/" . $filename);
        // Attack: Upload shell.php
    }
}

function test_upload_with_weak_validation() {
    if (isset($_FILES['file'])) {
        $filename = $_FILES['file']['name'];
        
        // Weak validation - just checking extension
        if (endsWith($filename, '.jpg')) {
            // But attacker could upload shell.php.jpg
            move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $filename);
        }
    }
}

// ============================================================================
// 9. INSECURE DIRECT OBJECT REFERENCES (IDOR)
// ============================================================================

function test_idor() {
    // CWE-639: Authorization Bypass Through User-Controlled Key
    
    $user_id = $_GET['user_id'];
    // No authorization check - any user can access any user's data
    $query = "SELECT * FROM users WHERE id = " . $user_id;
    $result = mysqli_query($GLOBALS["db"], $query);
}

// ============================================================================
// 10. SENSITIVE DATA EXPOSURE
// ============================================================================

function test_sensitive_data_logging() {
    // CWE-532: Insertion of Sensitive Information into Log File
    
    $password = $_POST['password'];
    // Logging password
    error_log("User login attempt with password: " . $password);
    
    // Displaying sensitive info to user
    echo "Database connection string: " . $GLOBALS['db_connection_string'];
}

function test_api_key_in_url() {
    // API key exposed in URL parameters
    $api_url = "https://api.example.com/data?api_key=" . $_GET['key'];
    // Better to use headers: Authorization: Bearer token
}

// ============================================================================
// 11. BROKEN AUTHENTICATION
// ============================================================================

function test_broken_authentication() {
    // CWE-287: Improper Authentication
    
    // Hardcoded credentials
    $correct_password = "admin123";
    
    if (isset($_POST['password'])) {
        if ($_POST['password'] == $correct_password) {
            // No rate limiting
            // No account lockout
            // No logging
            $_SESSION['authenticated'] = true;
        }
    }
}

function test_session_fixation() {
    // CWE-384: Session Fixation
    
    // Session ID taken from user input without regeneration
    if (isset($_GET['sessionid'])) {
        session_id($_GET['sessionid']);
        session_start();
    }
}

// ============================================================================
// 12. XML EXTERNAL ENTITY (XXE) INJECTION
// ============================================================================

function test_xxe_injection() {
    // CWE-611: Improper Restriction of XML External Entity Reference
    
    $xml_input = $_POST['xml'];
    $dom = new DOMDocument();
    
    // XXE vulnerability - allows entity expansion
    $dom->load('php://input');
    
    // Or with SimpleXML
    $xml = simplexml_load_string($xml_input);
    // Attack: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
}

// ============================================================================
// 13. OPEN REDIRECT
// ============================================================================

function test_open_redirect() {
    // CWE-601: URL Redirection to Untrusted Site
    
    $redirect_url = $_GET['redirect'];
    header("Location: " . $redirect_url);
    exit;
    // Attack: redirect=https://attacker.com
}

// ============================================================================
// 14. MISSING AUTHENTICATION
// ============================================================================

function test_missing_auth() {
    // CWE-306: Missing Authentication for Critical Function
    
    // Admin function with no authentication check
    if (isset($_POST['action']) && $_POST['action'] == 'delete_user') {
        $user_id = $_POST['user_id'];
        $query = "DELETE FROM users WHERE id = " . $user_id;
        mysqli_query($GLOBALS["db"], $query);
    }
}

// ============================================================================
// 15. RACE CONDITIONS
// ============================================================================

function test_race_condition() {
    // CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
    
    $file = "/tmp/counter.txt";
    $count = file_get_contents($file);
    $count++;
    
    // Race condition: Two requests could both read same value
    file_put_contents($file, $count);
}

?>
