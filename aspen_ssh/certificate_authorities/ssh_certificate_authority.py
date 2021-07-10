"""
SHA2 enhancement: implementation of rfc8332 section 3
rsa-sha2-512 to support SHA2 public key signing algorithm

.. module: aspen_ssh.ssh.certificate_authorities.ssh_certificate_authority
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from aspen_ssh.protocol.ssh_protocol import pack_ssh_string
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key


class SSHCertificateSignatureKeyType:
    RSA = 'ssh-rsa'
    RSA_SHA2 = 'rsa-sha2-512'
    ED25519 = 'ssh-ed25519'


class SSHCertificateAuthorityPrivateKeyType(object):
    RSA = '-----BEGIN RSA PRIVATE KEY-----\n'


class SSHCertificateAuthority:

    def __init__(self, pem_private_key: bytes, private_key_password: str = None):
        """
        RSA Certificate Authority used to sign certificates.

        :param pem_private_key: PEM formatted RSA Private Key.  It should be encrypted with a
        password, but that is not required.
        :param private_key_password: Password to decrypt the PEM RSA Private Key, if it is
        encrypted.  Which it should be.
        """
        self.public_key_type = None
        self.signing_key_type = None

        self.private_key = load_pem_private_key(
            pem_private_key, private_key_password, default_backend()
        )

    def sign(self, body):
        """
        Sign the certificate body with the CA private key.  Signatures are computed and
        encoded per RFC4253 section 6.6

        :param body: All other fields of the SSH Certificate, from the initial string to the
        signature key.
        :return: SSH Signature.
        """
        raise NotImplementedError("Child classes should override this")

    def get_signature_key(self) -> bytes:
        """
        Get the SSH Public Key associated with this CA.
        Packed per RFC4253 section 6.6

        :return: SSH Certificate formatted Public Key.
        """
        raise NotImplementedError("Child classes should override this")

    def _serialize_signature(self, signature: bytes) -> bytes:
        # pack signature block
        sig_inner = pack_ssh_string(self.signing_key_type)
        sig_inner += pack_ssh_string(signature)

        return pack_ssh_string(sig_inner)


__all__ = (
    'SSHCertificateAuthorityPrivateKeyType',
    'SSHCertificateSignatureKeyType',
    'SSHCertificateAuthority',
)
