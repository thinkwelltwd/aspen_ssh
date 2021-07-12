"""
.. module: bless.ssh.certificate_authorities.rsa_certificate_authority
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from aspen_ssh.certificate_authorities.ssh_certificate_authority import (
    SSHCertificateAuthority,
    SSHCertificateSignatureKeyType,
)
from aspen_ssh.public_keys import SSHPublicKeyType
from aspen_ssh.protocol.ssh_protocol import pack_ssh_mpint, pack_ssh_string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class RSACertificateAuthority(SSHCertificateAuthority):

    def __init__(self, pem_private_key, private_key_password=None, cert_type="sha2"):
        """
        RSA Certificate Authority used to sign certificates.

        :param pem_private_key: PEM formatted RSA Private Key.  It should be encrypted with a
        password, but that is not required.
        :param private_key_password: Password to decrypt the PEM RSA Private Key, if it is
        encrypted.  Which it should be.
        """
        super().__init__(pem_private_key, private_key_password)

        if cert_type == "sha1":
            self.public_key_type = SSHPublicKeyType.RSA
            self.signing_key_type = SSHCertificateSignatureKeyType.RSA
            self.algo = hashes.SHA1()
        else:
            self.public_key_type = SSHPublicKeyType.RSA
            self.signing_key_type = SSHCertificateSignatureKeyType.RSA_SHA2
            self.algo = hashes.SHA512()

        ca_pub_numbers = self.private_key.public_key().public_numbers()

        self.e = ca_pub_numbers.e
        self.n = ca_pub_numbers.n

    def get_signature_key(self) -> bytes:
        """
        Get the SSH Public Key associated with this CA.
        Packed per RFC4253 section 6.6.

        :return: SSH Public Key.
        """
        key = pack_ssh_string(self.public_key_type)
        key += pack_ssh_mpint(self.e)
        key += pack_ssh_mpint(self.n)
        return key

    def sign(self, body):
        """
        Sign the certificate body with the RSA private key.  Signatures are computed and
        encoded per RFC4253 section 6.6
        :param body: All other fields of the SSH Certificate, from the initial string to the
        signature key.
        :return: SSH RSA Signature.
        """
        signature = self.private_key.sign(body, padding.PKCS1v15(), self.algo)

        return self._serialize_signature(signature)


__all__ = [
    'RSACertificateAuthority',
]
