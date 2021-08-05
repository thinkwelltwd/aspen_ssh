class SSHCertificateParserError(Exception):
    pass


class UnsupportedKeyTypeError(SSHCertificateParserError):
    """This key has a type which we do not know how to parse"""


class InputTooShortError(SSHCertificateParserError):
    pass
