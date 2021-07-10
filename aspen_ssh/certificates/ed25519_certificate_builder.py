"""
.. module: aspen_ssh.ssh.certificates.ed25519_certificate_builder
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from aspen_ssh.certificates.ssh_certificate_builder import (
    SSHCertificateBuilder,
    SSHCertifiedKeyType,
    SSHCertificateType,
)
from aspen_ssh.protocol.ssh_protocol import pack_ssh_string
from aspen_ssh.public_keys import ED25519PublicKey


class ED25519CertificateBuilder(SSHCertificateBuilder):

    def __init__(self, ca, cert_type: SSHCertificateType, public_key: ED25519PublicKey):
        """
        Produces an SSH certificate for ED25519 public keys.

        :param ca: The SSHCertificateAuthority that will sign the certificate.  The
        SSHCertificateAuthority type does not need to be the same type as the
        SSHCertificateBuilder.
        :param cert_type: The SSHCertificateType.  Is this a User or Host certificate?  Some of
        the SSH Certificate fields do not apply or have a slightly different meaning depending on
        the certificate type.
        See https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys

        :param public_key: The ED25519PublicKey to issue a certificate for.
        """
        super().__init__(ca, cert_type)
        self.cert_key_type = SSHCertifiedKeyType.ED25519
        self.public_key = public_key
        self.public_key_comment = public_key.key_comment
        self.a = public_key.a

    def _serialize_ssh_public_key(self) -> bytes:
        """
        Serialize the Public Key into a string. This is not specified in
        https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
        but https://tools.ietf.org/id/draft-ietf-curdle-ssh-ed25519-02.html

        :return: The bytes that belong in the SSH Certificate between the nonce and the
        certificate serial number.
        """
        public_key = pack_ssh_string(self.a)
        return public_key


__all__ = [
    'ED25519CertificateBuilder',
]
