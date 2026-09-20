<?php
use Illuminate\Validation\Rules\Password;
// ruleid: laravel-password-min-length
$weak = Password::min(8);
// ok: laravel-password-min-length
$strong = Password::min(12)->mixedCase()->numbers();
