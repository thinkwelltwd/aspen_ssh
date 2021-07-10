"""
.. module: aspen_ssh.ssh.public_keys.ssh_public_key
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import base64
import hashlib
from cryptography.hazmat.primitives.serialization import load_ssh_public_key


class SSHPublicKeyTypeName:
    RSA = 'RSA'
    ED25519 = 'ED25519'


class SSHPublicKeyType:
    RSA = 'ssh-rsa'
    ED25519 = 'ssh-ed25519'


class SSHPublicKey:
    """
    Extracts the useful Public Key information from an SSH Public Key file.

    :param public_key: SSH Public Key file contents. (i.e. 'ssh-XXX AAAA....').
    """
    KEY_TYPE_NAME = ''

    def __init__(self, public_key: str):
        self.type = None
        self.key_comment = None

        try:
            self.public_key = load_ssh_public_key(public_key.encode('ascii'))
        except ValueError:
            raise ValueError("Public Key is not the correct type or format")

        split_ssh_public_key = public_key.split(' ')
        split_key_len = len(split_ssh_public_key)

        if split_key_len > 2:
            self.key_comment = ' '.join(split_ssh_public_key[2:])
        else:
            self.key_comment = ''

        key_bytes = base64.b64decode(split_ssh_public_key[1])
        fingerprint = hashlib.md5(key_bytes).hexdigest()

        self.fingerprint = f'{self.KEY_TYPE_NAME} ' + ':'.join(
            fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2)
        )


__all__ = (
    'SSHPublicKeyTypeName',
    'SSHPublicKeyType',
    'SSHPublicKey',
)
