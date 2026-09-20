<?php
// ruleid: constant-time-compare
if (hash_hmac('sha256', $m, $k) === $sig) {}
// ruleid: constant-time-compare
if ($sig != hash_hmac('sha256', $m, $k)) {}
// ok: constant-time-compare
if (hash_equals(hash_hmac('sha256', $m, $k), $sig)) {}
