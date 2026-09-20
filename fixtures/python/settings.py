import hashlib

DEBUG = True

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
]


def legacy_hash(password: bytes) -> str:
    return hashlib.md5(password).hexdigest()
