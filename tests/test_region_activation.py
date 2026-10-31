"""No live AWS network; Region enablement tested with isolated account clients."""
from unittest.mock import Mock
import pytest

from src.region_activation import get_opt_status, enable_opt_region


def session_with_status(status):
    client=Mock()
    client.get_region_opt_status.return_value={
        'RegionName':'me-central-1','RegionOptStatus':status
    }
    session=Mock()
    session.client.return_value=client
    return session,client


def test_disabled_region_can_be_enabled():
    session, client = session_with_status('DISABLED')
    assert enable_opt_region(session,'me-central-1')=='ENABLING'
    client.get_region_opt_status.assert_called_once_with(RegionName='me-central-1')
    client.enable_region.assert_called_once_with(RegionName='me-central-1')
    assert session.client.call_args.args == ('account',)
    assert session.client.call_args.kwargs['region_name']=='us-east-1'


@pytest.mark.parametrize('status', ['ENABLED','ENABLED_BY_DEFAULT','ENABLING','DISABLING'])
def test_not_disabled_never_calls_enable(status):
    session,client=session_with_status(status)
    assert enable_opt_region(session,'me-central-1')==status
    client.enable_region.assert_not_called()


def test_status_and_region_validation():
    session,client=session_with_status('ENABLING')
    assert get_opt_status(session,'me-central-1')=='ENABLING'
    for bad in ['bad', '', 'me-central-1;rm -rf /', 'x' * 110]:
        with pytest.raises(ValueError):
            get_opt_status(session,bad)
        with pytest.raises(ValueError):
            enable_opt_region(session,bad)
    client.enable_region.assert_not_called()


def test_unknown_status_fails_closed():
    session,client=session_with_status('SURPRISE')
    with pytest.raises(ValueError):
        enable_opt_region(session,'me-central-1')
    client.enable_region.assert_not_called()


def test_aws_access_denied_does_not_enable():
    session,client=session_with_status('DISABLED')
    client.get_region_opt_status.side_effect=PermissionError('denied')
    with pytest.raises(PermissionError):
        enable_opt_region(session,'me-central-1')
    client.enable_region.assert_not_called()



def test_region_access_denied_guidance_mentions_project_scp_not_only_iam():
    from src.region_activation import REGION_ACCESS_DENIED
    assert 'AccessDenied' in REGION_ACCESS_DENIED
    assert 'SCP' in REGION_ACCESS_DENIED
    assert 'AWS Builder ID' in REGION_ACCESS_DENIED
    assert 'Advanced Features' in REGION_ACCESS_DENIED
    assert 'AdministratorAccess' in REGION_ACCESS_DENIED
    assert '\\n' not in REGION_ACCESS_DENIED
