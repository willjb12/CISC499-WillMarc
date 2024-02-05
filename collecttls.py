import ssl
import socket
from urllib.parse import urlparse

def get_tls_info(currentwebsite):
    context = ssl.create_default_context()

    parsed = urlparse(currentwebsite)
    domain = parsed.netloc

    if parsed.scheme == "https":
        port = 443
    else:
        port = 81

    with socket.create_connection((domain, port)) as sock:
        with context.wrap_socket(sock, server_hostname = domain) as ssock:
            tls_version = ssock.version()
            cipher_suite = ssock.cipher()
            certificate = ssock.getpeercert()

            return tls_version, cipher_suite
