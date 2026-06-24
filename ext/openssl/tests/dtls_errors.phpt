--TEST--
Openssl\Dtls: error handling
--EXTENSIONS--
openssl
--SKIPIF--
<?php
if (!class_exists('Openssl\Dtls')) die('skip Openssl\Dtls not available');
?>
--FILE--
<?php
use Openssl\Dtls;
use Openssl\OpensslException;

// A certificate without a matching private key (and vice versa).
try {
    new Dtls(true, "cert", null);
} catch (OpensslException $e) {
    echo $e->getMessage(), "\n";
}

// Invalid PEM input.
try {
    new Dtls(true, "not a certificate", "not a key");
} catch (OpensslException $e) {
    echo $e->getMessage(), "\n";
}

$dtls = new Dtls(false);

// Unknown digest algorithm.
try {
    $dtls->getFingerprint('no-such-digest');
} catch (OpensslException $e) {
    echo $e->getMessage(), "\n";
}

// No peer certificate before the handshake.
var_dump($dtls->getPeerFingerprint());

// Keying material cannot be exported before the handshake completes.
var_dump($dtls->exportKeys('label', 16));

var_dump($dtls->isHandshakeFinished());
?>
--EXPECT--
Certificate and private key must be provided together
Failed to parse certificate or private key
Unknown digest algorithm
NULL
bool(false)
bool(false)
