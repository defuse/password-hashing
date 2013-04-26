<?php
require_once('PasswordHashClass.php');
$hash = PasswordHash::create_hash("password");
$good = PasswordHash::validate_password("password", $hash);
$bad =  PasswordHash::validate_password("wrong", $hash);
if ($good) {
    echo "pass\n";
} else {
    echo "fail\n";
}
if (!$bad) {
    echo "pass\n";
} else {
    echo "fail\n";
}
?>
