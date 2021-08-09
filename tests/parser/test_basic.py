import datetime

from aspen_ssh.parser import SSHCertificate


def test_rsa_cert(mocker):
    with open('tests/parser/data/web1_rsa_key-cert.pub', 'rb') as f:
        cert = SSHCertificate.from_bytes(f.read())
    assert cert.key_type == 'ssh-rsa-cert-v01@openssh.com'
    assert cert.valid_after == datetime.datetime(2018, 10, 9, 0, 2, 41)
    assert cert.valid_before == datetime.datetime(2019, 10, 15, 0, 2, 41)
    assert cert.key_id == 'web1'
    assert cert.principals == ['web1.example.com']
    assert cert.serial == 1
    mocker.patch(
        'aspen_ssh.parser.certificate.utcnow',
        return_value=datetime.datetime(2018, 10, 9, 0, 2, 39)
    )
    assert cert.remaining_validity == 0
    mocker.patch(
        'aspen_ssh.parser.certificate.utcnow',
        return_value=datetime.datetime(2018, 10, 9, 0, 2, 41)
    )
    assert cert.remaining_validity == 32054400.0
    mocker.patch(
        'aspen_ssh.parser.certificate.utcnow',
        return_value=datetime.datetime(2019, 10, 16, 0, 2, 41)
    )
    assert cert.remaining_validity == 0
    d = cert.asdict()
    assert d['cert_type'] == 'SSH2_CERT_TYPE_HOST'
    assert d['critical_options'] == []
    assert d['extensions'] == []


def test_ed25519_cert():
    with open('tests/parser/data/web1_ed25519_key-cert.pub', 'rb') as f:
        cert = SSHCertificate.from_bytes(f.read())
    assert cert.key_type == 'ssh-ed25519-cert-v01@openssh.com'
    assert cert.valid_after == datetime.datetime(2018, 10, 9, 0, 8, 1)
    assert cert.valid_before == datetime.datetime(2019, 10, 15, 0, 8, 1)
    assert cert.key_id == 'web1'
    assert cert.principals == ['web1.example.com']
    assert cert.serial == 1
    d = cert.asdict()
    assert d['cert_type'] == 'SSH2_CERT_TYPE_HOST'
    assert d['critical_options'] == []
    assert d['extensions'] == []


def test_dsa_cert():
    with open('tests/parser/data/web2_dsa_key-cert.pub', 'rb') as f:
        cert = SSHCertificate.from_bytes(f.read())
    assert cert.key_type == 'ssh-dss-cert-v01@openssh.com'
    assert cert.valid_after == datetime.datetime(2018, 10, 9, 0, 11, 55)
    assert cert.valid_before == datetime.datetime(2019, 10, 15, 0, 11, 55)
    assert cert.key_id == 'web2'
    assert cert.principals == ['web2.example.com']
    assert cert.serial == 2
    d = cert.asdict()
    assert d['cert_type'] == 'SSH2_CERT_TYPE_HOST'
    assert d['critical_options'] == []
    assert d['extensions'] == []


def test_forever_valid_cert():
    with open('tests/parser/data/forever_valid_host_key.pub', 'rb') as f:
        cert = SSHCertificate.from_bytes(f.read())
    assert cert.valid_after == datetime.datetime(1970, 1, 1, 0, 0, 0)
    today = datetime.datetime.now().replace(minute=0, hour=0, second=0, microsecond=0)
    valid_before = today.replace(year=today.year + 1000)
    assert cert.valid_before == valid_before
