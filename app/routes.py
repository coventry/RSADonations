import ssl
from OpenSSL import crypto

from app import app

@app.route('/')
@app.route('/index')
def index():
    return "Hello, World!"

@app.route('/ssl_key/<domain>')
def ssl_key(domain):
    print 'domain', domain
    cert = ssl.get_server_certificate((domain, 443))
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    openssl_pubkey = x509.get_pubkey()
    crypto_pubkey = openssl_pubkey.to_cryptography_key()
    keyParams = crypto_pubkey.public_numbers()
    return repr(dict(e=keyParams.e, n=keyParams.n, size=crypto_pubkey.key_size))

