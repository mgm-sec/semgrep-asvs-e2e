import hmac


def verify(key, message, signature):
    return hmac.new(key, message, "sha256").hexdigest() == signature
