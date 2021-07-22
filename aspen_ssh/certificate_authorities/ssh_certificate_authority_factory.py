"""
.. module: aspen_ssh.ssh.certificate_authorities.ssh_certificate_authority_factory
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from typing import Literal

from aspen_ssh.certificate_authorities import (
    Ed25519CertificateAuthority,
    RSACertificateAuthority,
    SSHCertificateAuthority,
    PrivateKeys,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def get_ssh_certificate_authority(
    private_key: PrivateKeys,
    password: str = None,
    cert_type: Literal['sha2', 'sha1'] = 'sha2',
) -> SSHCertificateAuthority:
    """
    Returns the proper SSHCertificateAuthority instance based off the private_key type.

    :param private_key: ASCII bytes of an SSH compatible Private Key (e.g., PEM or SSH Protocol 2 Private Key).
    It should be encrypted with a password, but that is not required.
    :param password: ASCII bytes of the Password to decrypt the Private Key, if it is encrypted.  Which it should be.
    :param cert_type: Sha version expected ("sha2" or "sha1")
    :return: An SSHCertificateAuthority instance.
    """
    if isinstance(private_key, bytes):
        private_key = load_pem_private_key(private_key, password, default_backend())

    ca_data = {
        'pem_private_key': private_key,
        'private_key_password': password,
    }

    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return Ed25519CertificateAuthority(**ca_data)

    if isinstance(private_key, rsa.RSAPrivateKey):
        ca_data['cert_type'] = cert_type
        return RSACertificateAuthority(**ca_data)

    else:
        raise TypeError('Unsupported CA Private Key Type')


__all__ = [
    'get_ssh_certificate_authority',
]
