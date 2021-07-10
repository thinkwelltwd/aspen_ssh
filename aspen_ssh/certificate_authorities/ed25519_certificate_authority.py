"""
.. module: aspen_ssh.ssh.certificate_authorities.rsa_certificate_authority
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from aspen_ssh.certificate_authorities.ssh_certificate_authority import (
    SSHCertificateAuthority,
    SSHCertificateSignatureKeyType,
)
from aspen_ssh.protocol.ssh_protocol import pack_ssh_string
from aspen_ssh.public_keys.ssh_public_key import SSHPublicKeyType
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


class Ed25519CertificateAuthority(SSHCertificateAuthority):

    def __init__(self, pem_private_key: bytes, private_key_password: str = None):
        """
        RSA Certificate Authority used to sign certificates.

        :param pem_private_key: PEM formatted RSA Private Key.  It should be encrypted with a
        password, but that is not required.
        :param private_key_password: Password to decrypt the PEM RSA Private Key, if it is
        encrypted.  Which it should be.
        """
        super().__init__(pem_private_key, private_key_password)
        self.public_key_type = SSHPublicKeyType.ED25519
        self.signing_key_type = SSHCertificateSignatureKeyType.ED25519

        self.a = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def get_signature_key(self) -> bytes:
        """
        Get the SSH Public Key associated with this CA.
        Packed per RFC4253 section 6.6.

        :return: SSH Public Key.
        """
        key = pack_ssh_string(self.public_key_type)
        key += pack_ssh_string(self.a)
        return key

    def sign(self, body: bytes) -> bytes:
        """
        Sign the certificate body with the RSA private key.  Signatures are computed and
        encoded per RFC4253 section 6.6

        :param body: All other fields of the SSH Certificate, from the initial string to the
        signature key.
        :return: SSH RSA Signature.
        """
        signature = self.private_key.sign(body)
        return self._serialize_signature(signature)


__all__ = [
    'Ed25519CertificateAuthority',
]
