<?php
if (!isset($_GET['path'])) {
    die('<b>Error:</b> Missing \'path\' parameter.');
}

// Check for LFI attacks
$path = $_GET['path'];

$badwords = array("../", "etc/passwd", ".ssh");
foreach ($badwords as $badword) {
    if (strpos($path, $badword) !== false) {
        die('<b>Error:</b> Attack detected.');
    }
}

// Normalize path
$path = urldecode($path);

// Return the image
header('Content-Type: image/png');
echo file_get_contents('/var/www/html/images/' . $path);
?>