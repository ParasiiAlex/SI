<?php

include_once "AESCounter.php";

$text = "abc";

$datetime = microtime(true);

$encrypted = AESCounter::encrypt($text, 'password', 128);
echo $encrypted.PHP_EOL;
$decrypted = AESCounter::decrypt($encrypted, 'password', 128);
echo $decrypted.PHP_EOL;

echo microtime(true) - $datetime;