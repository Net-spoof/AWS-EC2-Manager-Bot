"""Change an existing EC2 root password over verified SSH; never store passwords.

Caller must fetch the public IP via EC2 DescribeInstances, verify the SSH host-key
fingerprint with the user, and only then request the existing root password.
"""
import base64
import hashlib
import hmac
import ipaddress
import socket

import paramiko
from .aws_api import make_password


def _valid_ip(ip):
    try:
        if not ipaddress.ip_address(ip).is_global or ipaddress.ip_address(ip).version != 4:
            raise ValueError('Server has no valid public IPv4')
    except ValueError as exc:
        raise ValueError('Server has no valid public IPv4') from exc
    return ip


def _fingerprint(key):
    digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode('ascii').rstrip('=')
    return f'{key.get_name()} SHA256:{digest}'


def ssh_fingerprint(ip):
    _valid_ip(ip)
    with socket.create_connection((ip, 22), timeout=9) as sock:
        with paramiko.Transport(sock) as transport:
            transport.start_client(timeout=12)
            return _fingerprint(transport.get_remote_server_key())


def change_root_password(ip, existing_password, verified_fingerprint):
    _valid_ip(ip)
    if not existing_password or not verified_fingerprint:
        raise ValueError('Missing authentication details')
    new_password = make_password(length=30)
    with socket.create_connection((ip, 22), timeout=9) as sock:
        with paramiko.Transport(sock) as transport:
            transport.start_client(timeout=12)
            actual = _fingerprint(transport.get_remote_server_key())
            if not hmac.compare_digest(actual, verified_fingerprint):
                raise ValueError('SSH host key changed! Password change cancelled.')
            try:
                transport.auth_password('root', existing_password)
            except paramiko.AuthenticationException as exc:
                raise ValueError('Current root password was rejected by SSH') from exc
            if not transport.is_authenticated():
                raise ValueError('SSH root authentication failed')
            with transport.open_session(timeout=12) as chan:
                chan.settimeout(20)
                chan.exec_command('chpasswd')
                # chpasswd reads stdin over encrypted SSH; no password in shell args/logs.
                chan.sendall(f'root:{new_password}\n'.encode('utf-8'))
                chan.shutdown_write()
                status = chan.recv_exit_status()
                if status != 0:
                    raise ValueError('Remote chpasswd failed; existing password is unchanged')
    return new_password
