"""
.. module: aspen_ssh.ssh.public_keys.rsa_public_key
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from aspen_ssh.public_keys.ssh_public_key import SSHPublicKey, SSHPublicKeyType, SSHPublicKeyTypeName
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from typing import TYPE_CHECKING


def check_small_primes(n):
    """
    Returns True if n is divisible by a number in SMALL_PRIMES.
    Based on the MPL licensed
    https://github.com/letsencrypt/boulder/blob/58e27c0964a62772e7864e8a12e565ef8a975035/core/good_key.go
    """
    small_primes = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
        191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
        401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
        509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
        631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743,
        751
    ]
    for prime in small_primes:
        if n % prime == 0:
            return True

    return False


class RsaPublicKey(SSHPublicKey):

    KEY_TYPE_NAME = SSHPublicKeyTypeName.RSA

    if TYPE_CHECKING:
        public_key: RSAPublicKey

    def __init__(self, public_key: str):
        """
        Extracts the useful RSA Public Key information from an SSH Public Key file.

        :param public_key: SSH Public Key file contents.
        (i.e. 'ssh-rsa AAAAB3NzaC1yc2E..').
        """
        super().__init__(public_key)

        self.type = SSHPublicKeyType.RSA

        ca_pub_numbers = self.public_key.public_numbers()
        if not isinstance(ca_pub_numbers, RSAPublicNumbers):
            raise TypeError("Public Key is not the correct type or format")

        self.key_size = self.public_key.key_size
        self.e = ca_pub_numbers.e
        self.n = ca_pub_numbers.n

    def validate_for_signing(self):
        """
        Raises an error if the public key looks weak
        """
        if (self.key_size < 2048 or self.e < 65537 or self.n % 2 == 0
                or check_small_primes(self.n)):
            raise ValueError("Unsafe RSA public key")


__all__ = [
    'RsaPublicKey',
]
