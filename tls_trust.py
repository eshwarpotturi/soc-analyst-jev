"""Make Python's TLS use the operating system's certificate store.

Corporate networks often run a TLS-inspecting proxy that re-signs HTTPS traffic
with a private root CA. That CA is installed in the OS/browser trust store, so
browsers and pip work, but Python's bundled certificate set does not include it
and raises `CERTIFICATE_VERIFY_FAILED: self-signed certificate in certificate
chain`.

`enable_os_trust()` routes Python's certificate verification through the OS trust
store (via the `truststore` package), so the corporate CA is trusted the same way
the browser trusts it. Verification stays ON — this never disables it. It is a
no-op if `truststore` is not installed, so environments without an intercepting
proxy are unaffected.
"""
from __future__ import annotations


def enable_os_trust() -> bool:
    """Route TLS verification through the OS trust store. Returns True on success.

    Safe to call more than once and safe to call when `truststore` is absent
    (returns False, leaving default verification in place).
    """
    try:
        import truststore

        truststore.inject_into_ssl()
        return True
    except Exception:
        return False
