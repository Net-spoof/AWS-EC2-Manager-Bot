"""Tests use an SSH transport stub: never connect to a real server."""
import importlib
import sys
from unittest.mock import Mock
import pytest


def load_module(monkeypatch):
    # This stub allows offline tests when paramiko wheels aren't available in the runner.
    monkeypatch.setitem(sys.modules,'paramiko', Mock(AuthenticationException=type('SSHAuthFailure',(Exception,),{})))
    sys.modules.pop('src.ssh_password',None)
    return importlib.import_module('src.ssh_password')


def test_fingerprint_format_and_public_ip_requirement(monkeypatch):
    m=load_module(monkeypatch)
    key=Mock(); key.asbytes.return_value=b'test-host-key'; key.get_name.return_value='ssh-ed25519'
    fingerprint=m._fingerprint(key)
    assert fingerprint.startswith('ssh-ed25519 SHA256:')
    assert fingerprint==m._fingerprint(key)
    with pytest.raises(ValueError):m._valid_ip('127.0.0.1')
    with pytest.raises(ValueError):m._valid_ip('10.1.1.1')
    with pytest.raises(ValueError):m._valid_ip('example.com')
    assert m._valid_ip('13.62.52.94')=='13.62.52.94'


def test_password_rotation_verifies_fingerprint_before_auth(monkeypatch):
    m=load_module(monkeypatch)
    m.make_password=lambda length:'N'*length
    key=Mock();key.asbytes.return_value=b'host-key';key.get_name.return_value='ssh-ed25519'
    channel=Mock();channel.recv_exit_status.return_value=0
    channel.__enter__=Mock(return_value=channel);channel.__exit__=Mock(return_value=False)
    transport=Mock();transport.get_remote_server_key.return_value=key
    transport.is_authenticated.return_value=True
    transport.open_session.return_value=channel
    transport.__enter__=Mock(return_value=transport);transport.__exit__=Mock(return_value=False)
    sock=Mock();sock.__enter__=Mock(return_value=sock);sock.__exit__=Mock(return_value=False)
    monkeypatch.setattr(m.socket,'create_connection',lambda *args,**kwargs:sock)
    m.paramiko.Transport=lambda s:transport
    with pytest.raises(ValueError,match='host key changed'):
        m.change_root_password('13.62.52.94','oldpassword','not-valid')
    transport.auth_password.assert_not_called()
    new=m.change_root_password('13.62.52.94','oldpassword',m._fingerprint(key))
    assert new=='N'*30
    transport.auth_password.assert_called_with('root','oldpassword')
    channel.exec_command.assert_called_with('chpasswd')
    channel.sendall.assert_called_with(b'root:'+b'N'*30+b'\n')
