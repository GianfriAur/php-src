--TEST--
Openssl\Dtls: handshake, keying material export and application data
--EXTENSIONS--
openssl
--SKIPIF--
<?php
if (!class_exists('Openssl\Dtls')) die('skip Openssl\Dtls not available');
?>
--FILE--
<?php
use Openssl\Dtls;

$server = new Dtls(true);
$client = new Dtls(false);

// A fingerprint is available before the handshake.
var_dump(strlen($server->getFingerprint()) > 0);
var_dump(strlen($client->getFingerprint('sha256')) > 0);

function pump(Dtls $from, Dtls $to): void {
    while (($datagram = $from->pull()) !== null) {
        $to->feed($datagram);
    }
}

$serverDone = $clientDone = false;
for ($i = 0; $i < 50 && !($serverDone && $clientDone); $i++) {
    if (!$clientDone && $client->handshake() === 1) {
        $clientDone = true;
    }
    pump($client, $server);
    if (!$serverDone && $server->handshake() === 1) {
        $serverDone = true;
    }
    pump($server, $client);
}
var_dump($serverDone && $clientDone);

// Both peers derive identical keying material (RFC 5705).
$serverKeys = $server->exportKeys('EXTRACTOR-dtls_srtp', 60);
$clientKeys = $client->exportKeys('EXTRACTOR-dtls_srtp', 60);
var_dump(strlen($serverKeys) === 60);
var_dump($serverKeys === $clientKeys);

// Application data round trip.
$server->write('ping');
pump($server, $client);
var_dump($client->read());
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
string(4) "ping"
