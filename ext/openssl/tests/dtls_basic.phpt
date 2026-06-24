--TEST--
Openssl\Dtls: handshake, peer fingerprint, keying material and application data
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

var_dump(strlen($server->getFingerprint()) > 0);
var_dump($server->isHandshakeFinished());

function pump(Dtls $from, Dtls $to): void {
    while (($datagram = $from->pull()) !== null) {
        $to->feed($datagram);
    }
}

for ($i = 0; $i < 50 && !($server->isHandshakeFinished() && $client->isHandshakeFinished()); $i++) {
    $client->handshake();
    pump($client, $server);
    $server->handshake();
    pump($server, $client);
}
var_dump($server->isHandshakeFinished() && $client->isHandshakeFinished());

// Each peer sees the other's certificate fingerprint.
var_dump($client->getPeerFingerprint() === $server->getFingerprint());
var_dump($server->getPeerFingerprint() === $client->getFingerprint());

// Both peers derive identical keying material (RFC 5705).
$serverKeys = $server->exportKeys('EXTRACTOR-dtls_srtp', 60);
$clientKeys = $client->exportKeys('EXTRACTOR-dtls_srtp', 60);
var_dump($serverKeys === $clientKeys);

// Application data round trip.
$server->write('ping');
pump($server, $client);
var_dump($client->read());

var_dump(Dtls::HANDSHAKE_FINISHED);
?>
--EXPECT--
bool(true)
bool(false)
bool(true)
bool(true)
bool(true)
bool(true)
string(4) "ping"
int(1)
