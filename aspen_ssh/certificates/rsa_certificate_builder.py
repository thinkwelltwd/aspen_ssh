"""
.. module: aspen_ssh.ssh.certificates.rsa_certificate_builder
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from typing import TYPE_CHECKING
from aspen_ssh.certificates.ssh_certificate_builder import (
    SSHCertificateBuilder,
    SSHCertifiedKeyType,
    SSHCertificateType,
)
from aspen_ssh.protocol.ssh_protocol import pack_ssh_mpint

if TYPE_CHECKING:
    from aspen_ssh.certificate_authorities import SSHCertificateAuthority
    from aspen_ssh.public_keys import RsaPublicKey


class RSACertificateBuilder(SSHCertificateBuilder):

    def __init__(
            self,
            ca: 'SSHCertificateAuthority',
            cert_type: SSHCertificateType,
            public_key: 'RsaPublicKey',
    ):
        """
        Produces an SSH certificate for RSA public keys.

        :param ca: The SSHCertificateAuthority that will sign the certificate.  The
        SSHCertificateAuthority type does not need to be the same type as the
        SSHCertificateBuilder.
        :param cert_type: The SSHCertificateType.  Is this a User or Host certificate?  Some of
        the SSH Certificate fields do not apply or have a slightly different meaning depending on
        the certificate type.
        See https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
        :param public_key: The RSAPublicKey to issue a certificate for.
        """
        super().__init__(ca, cert_type)
        self.cert_key_type = SSHCertifiedKeyType.RSA
        self.public_key = public_key
        self.public_key_comment = public_key.key_comment
        self.e = public_key.e
        self.n = public_key.n

    def _serialize_ssh_public_key(self) -> bytes:
        """
        Serialize the Public Key into the RSA exponent and public modulus stored as SSH mpints.
        https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys

        :return: The bytes that belong in the SSH Certificate between the nonce and the
        certificate serial number.
        """
        public_key = pack_ssh_mpint(self.e)
        public_key += pack_ssh_mpint(self.n)
        return public_key


__all__ = [
    'RSACertificateBuilder',
]
