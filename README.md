# AspenSSH - An SSH CA library

SSH Certificates are an excellent way to authorize users to access a particular SSH host,
as they can be restricted for a single use case, and can be short-lived.  Instead of managing the
authorized_keys of a host, or controlling who has access to SSH Private Keys, hosts just
need to be configured to trust an SSH CA.

## Getting Started
These instructions are to get started with AspenSSH in your local development environment.

### Installation Instructions
Clone the repo:

    $ git clone git@github.com:thinkwell/aspen_ssh.git

Cd to the aspen_ssh repo:

    $ cd aspen_ssh

Create a virtualenv if you haven't already:

    $ python3.9 -m venv venv

Activate the venv:

    $ source venv/bin/activate

Install package and test dependencies:

    (venv) $ make develop

Run the tests:

    (venv) $ make test


## Verifying Certificates
You can inspect the contents of a certificate with ssh-keygen directly:

    $ ssh-keygen -L -f your-cert.pub

## Enabling AspenSSH Certificates On Servers
Add the following line to `/etc/ssh/sshd_config`:

    TrustedUserCAKeys /etc/ssh/cas.pub

Add a new file, owned by and only writable by root, at `/etc/ssh/cas.pub` with the contents:

    ssh-rsa AAAAB3NzaC1yc2EAAAADAQ…  #id_rsa.pub of an SSH CA
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQ…  #id_rsa.pub of an offline SSH CA
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQ…  #id_rsa.pub of an offline SSH CA 2

To simplify SSH CA Key rotation you should provision multiple CA Keys, and leave them offline until
you are ready to rotate them.

Additional information about the TrustedUserCAKeys file is [here](https://www.freebsd.org/cgi/man.cgi?sshd_config(5))

## Project resources
- Source code <https://github.com/thinkwelltwd/aspen_ssh>
- Issue tracker <https://github.com/thinkwelltwd/aspen_ssh/issues>
