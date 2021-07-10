"""
.. module: aspen_ssh.ssh.certificate_authorities.ssh_certificate_authority_factory
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from aspen_ssh.certificate_authorities import (
    RSACertificateAuthority,
    SSHCertificateAuthority,
)
from aspen_ssh.certificate_authorities.ssh_certificate_authority import (
    SSHCertificateAuthorityPrivateKeyType,
)


def get_ssh_certificate_authority(
        private_key: bytes,
        password: str = None,
        cert_type="sha2",
) -> SSHCertificateAuthority:
    """
    Returns the proper SSHCertificateAuthority instance based off the private_key type.

    :param private_key: ASCII bytes of an SSH compatible Private Key (e.g., PEM or SSH Protocol 2 Private Key).
    It should be encrypted with a password, but that is not required.
    :param password: ASCII bytes of the Password to decrypt the Private Key, if it is encrypted.  Which it should be.
    :param cert_type: Sha version expected ("sha2" or "sha1")
    :return: An SSHCertificateAuthority instance.
    """
    if private_key.decode('ascii').startswith(SSHCertificateAuthorityPrivateKeyType.RSA):
        return RSACertificateAuthority(
            pem_private_key=private_key,
            private_key_password=password,
            cert_type=cert_type,
        )

    else:
        raise TypeError("Unsupported CA Private Key Type")


__all__ = [
    'get_ssh_certificate_authority'
]
