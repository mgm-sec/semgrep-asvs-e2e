AUTH_PASSWORD_VALIDATORS = [
    # ruleid: django-password-min-length
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    # ruleid: django-password-min-length
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    # ok: django-password-min-length
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    # ok: django-password-min-length
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
]
