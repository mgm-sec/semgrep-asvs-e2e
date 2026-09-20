<?php
use Illuminate\Validation\Rules\Password;

putenv("APP_DEBUG=true");

function verify($k, $m, $sig) {
    return hash_hmac('sha256', $m, $k) === $sig;
}

$rule = Password::min(8);
