import hmac


def verify(k, m, sig):
    # ruleid: constant-time-compare
    if hmac.new(k, m, "sha256").hexdigest() == sig:
        return True
    # ruleid: constant-time-compare
    if sig != hmac.new(k, m, "sha256").digest():
        return False
    # ok: constant-time-compare
    return hmac.compare_digest(hmac.new(k, m, "sha256").hexdigest(), sig)
