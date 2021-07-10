"""
.. module: aspen_ssh.ssh.public_keys.ed25519_public_key
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from typing import TYPE_CHECKING


from .ssh_public_key import SSHPublicKey, SSHPublicKeyType, SSHPublicKeyTypeName


class ED25519PublicKey(SSHPublicKey):

    KEY_TYPE_NAME = SSHPublicKeyTypeName.ED25519

    if TYPE_CHECKING:
        public_key: Ed25519PublicKey

    def __init__(self, public_key: str):
        """
        Extracts the useful RSA Public Key information from an SSH Public Key file.

        :param public_key: SSH Public Key file contents.
        (i.e. 'ssh-ed25519 AAAAB3NzaC1yc2E..').
        """
        super().__init__(public_key)

        self.type = SSHPublicKeyType.ED25519

        self.a = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


__all__ = [
    'ED25519PublicKey',
]
