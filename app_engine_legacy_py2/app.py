import logging
import socket
import ssl
import StringIO
import webapp2

_SERVER_ADDRESS = ('localhost', 7000)


_CLIENT_CERT = '''-----BEGIN CERTIFICATE-----
MIIBWzCCAQECCQDb0mKoaGhw0zAKBggqhkjOPQQDAjA0MRQwEgYDVQQKDAtFeGFt
cGxlIEluYzEcMBoGA1UEAwwTRXhhbXBsZSBJbmMgUm9vdCBDQTAeFw0xOTExMjEx
ODIxNDNaFw0yMjExMjAxODIxNDNaMDcxFDASBgNVBAoMC0V4YW1wbGUgSW5jMR8w
HQYDVQQDDBZjbGllbnRjZXJ0LmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAE/7f/6WkXIuJHwccnc3ZSHrfPc0VlCDIgUKUZFIlyy1eUU8iOOWpM
wFEUG14UFC5MQyhEG7tpJUpZ806tXV3SWDAKBggqhkjOPQQDAgNIADBFAiEA7qwr
RWJW3qFsLo5SjXItRxzR4B3Nf5jTlLHOz5FWxoMCICE+7oANYiHkHpMxrQXH9WGL
nWpKM+q5w1aJu/3z+EVe
-----END CERTIFICATE-----'''

_CLIENT_KEY = '''-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK8FxCmhDoE2JS7I/rE/roEt5LRRsjuhuWzMv+ZsnsR8oAoGCCqGSM49
AwEHoUQDQgAE/7f/6WkXIuJHwccnc3ZSHrfPc0VlCDIgUKUZFIlyy1eUU8iOOWpM
wFEUG14UFC5MQyhEG7tpJUpZ806tXV3SWA==
-----END EC PRIVATE KEY-----'''


class SSLWrapper(object):
    """Wraps a socket using a client key and certificate.

       This code only works in App Engine which has a special
       implementation of ssl.wrap_socket that allows StringIO
       instances for the keyfile and certfile arguments. See:

       https://cloud.google.com/appengine/docs/standard/python/sockets/ssl_support
    """

    def __init__(self, client_cert, client_key):
        self.client_cert = client_cert
        self.client_key = client_key

    def wrap_socket(self, sock):
        return ssl.wrap_socket(
            sock,
            server_side=False,
            keyfile=StringIO.StringIO(self.client_key),
            certfile=StringIO.StringIO(self.client_cert),
        )

class HelloHandler(webapp2.RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain;charset=utf-8'
        self.response.write('hello\n')
        logging.info('hello')

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # plain TLS with no client certificate (default trusts any server)
            # sock = ssl.wrap_socket(sock, server_side=False)

            client_key_ssl_wrapper = SSLWrapper(_CLIENT_CERT, _CLIENT_KEY)
            sock = client_key_ssl_wrapper.wrap_socket(sock)
            logging.info('connecting to %r ...', _SERVER_ADDRESS)
            sock.connect(_SERVER_ADDRESS)

            sock.sendall('hello\n')

            # TODO: Should read until newline
            output = sock.recv(4096)

            self.response.write('type of socket: {!r}\n'.format(sock))
            self.response.write('from socket: {!r}\n'.format(output))
            logging.info('socket output: %r', output)
        finally:
            sock.close()


app = webapp2.WSGIApplication([
  ('/', HelloHandler),
])
