import base64
import hashlib
import enum
from datetime import datetime, timedelta

from .exceptions import UnsupportedKeyTypeError
from .helpers import (
    take_list,
    take_u32,
    take_u64,
    take_pascal_bytestring,
    take_pascal_string,
)


class CertType(enum.Enum):
    SSH2_CERT_TYPE_USER: int = 1
    SSH2_CERT_TYPE_HOST: int = 2


class PublicKey(object):

    def __init__(self, raw: bytes):
        self.raw = raw

    @property
    def fingerprint(self):
        dgt = hashlib.sha256(self.raw).digest()
        b64 = base64.standard_b64encode(dgt).decode('ascii')
        return f"SHA256:{b64.rstrip('=')}"


class RSAPublicKey(PublicKey):

    def __init__(self, raw: bytes, modulus: bytes, exponent: int):
        super().__init__(raw)
        self.modulus = modulus
        self.exponent = exponent


def take_rsa_cert(raw_pubkey, byte_array):
    modulus_len, byte_array = take_u32(byte_array)
    modulus = byte_array[:modulus_len]
    byte_array = byte_array[modulus_len:]
    exponent_len, byte_array = take_u32(byte_array)
    exponent = byte_array[:exponent_len]
    return RSAPublicKey(modulus=modulus, exponent=exponent, raw=raw_pubkey)


def utcnow():
    return datetime.utcnow()  # pragma: no cover


class SSHCertificate:

    def __init__(
        self,
        serial: str,
        cert_type: CertType,
        key_id: str,
        principals: list,
        valid_after: datetime,
        valid_before: datetime,
        critical_options: list,
        extensions: list,
        signature: str,
        key_type: str,
        pubkey_parts: dict,
    ):
        self.serial = serial
        self.cert_type = cert_type
        self.key_id = key_id
        self.principals = principals
        self.valid_after = valid_after
        self.valid_before = valid_before
        self.critical_options = critical_options
        self.extensions = extensions
        self.signature = signature
        self.key_type = key_type
        self.pubkey_parts = pubkey_parts

    def __str__(self):
        return f'{self.key_type!r} Type: {self.cert_type.name!r} ' \
               f'Valid from: {self.valid_after!r}-{self.valid_before!r}'

    def __repr__(self):
        return f'{self.__class__.__name__}({self.__str__()})'

    def asdict(self):
        parts = dict((k, base64.b64encode(v).decode('ascii')) for k, v in self.pubkey_parts.items())
        return {
            'valid_after': self.valid_after.isoformat(),
            'valid_before': self.valid_before.isoformat(),
            'cert_type': self.cert_type.name,
            'signature': base64.b64encode(self.signature).decode('ascii'),
            'critical_options': self.critical_options,
            'extensions': self.extensions,
            'pubkey_parts': parts,
        }

    @classmethod
    def from_bytes(cls, byte_array):
        if b' ' in byte_array:
            blob = byte_array.split(b' ')[1]
        else:
            blob = byte_array
        blob = base64.b64decode(blob)
        key_type, blob = take_pascal_string(blob)
        pubkey_parts = {}
        if key_type == 'ssh-rsa-cert-v01@openssh.com':
            pubkey_parts['nonce'], blob = take_pascal_bytestring(blob)
            pubkey_parts['n'], blob = take_pascal_bytestring(blob)
            pubkey_parts['e'], blob = take_pascal_bytestring(blob)
        elif key_type == 'ssh-ed25519-cert-v01@openssh.com':
            pubkey_parts['nonce'], blob = take_pascal_bytestring(blob)
            pubkey_parts['pubkey'], blob = take_pascal_bytestring(blob)
        elif key_type == 'ssh-dss-cert-v01@openssh.com':
            pubkey_parts['nonce'], blob = take_pascal_bytestring(blob)
            pubkey_parts['p'], blob = take_pascal_bytestring(blob)
            pubkey_parts['q'], blob = take_pascal_bytestring(blob)
            pubkey_parts['g'], blob = take_pascal_bytestring(blob)
            pubkey_parts['pubkey'], blob = take_pascal_bytestring(blob)
        else:
            raise UnsupportedKeyTypeError(key_type)
        serial, blob = take_u64(blob)
        cert_type, blob = take_u32(blob)
        cert_type = CertType(cert_type)
        key_id, blob = take_pascal_string(blob)
        principals, blob = take_list(blob, take_pascal_string)
        valid_after, blob = take_u64(blob)
        valid_after = datetime.utcfromtimestamp(valid_after)
        valid_before, blob = take_u64(blob)
        try:
            valid_before = datetime.utcfromtimestamp(valid_before)
        except OverflowError:
            # if valid forever, then set expiration at 1000 years from today
            today = datetime.now().replace(minute=0, hour=0, second=0, microsecond=0)
            valid_before = today.replace(year=today.year + 1000)
        critical_options, blob = take_list(blob, take_pascal_string)
        extensions, blob = take_list(blob, take_pascal_string)
        unknown, blob = take_pascal_bytestring(blob)
        raw_ca, blob = take_pascal_bytestring(blob)

        signature = blob

        return SSHCertificate(
            serial,
            cert_type,
            key_id,
            principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            signature,
            key_type,
            pubkey_parts,
        )

    @property
    def remaining_validity(self):
        now = utcnow()
        if now > self.valid_before or now < self.valid_after:
            return 0
        else:
            return (self.valid_before - now).total_seconds()


__all__ = [
    'SSHCertificate',
]
