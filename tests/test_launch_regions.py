"""No EC2 resources are created during account/Region filtering."""
from unittest.mock import Mock

from botocore.exceptions import ClientError

from src import launch_regions


def aws_error(code, operation, message='not permitted'):
    return ClientError({'Error': {'Code': code, 'Message': message}}, operation)


def fake_region(result='allowed'):
    ec2, ssm = Mock(), Mock()
    ec2.describe_vpcs.return_value = {'Vpcs': [{'VpcId': 'vpc-123'}]}
    ec2.describe_subnets.return_value = {'Subnets': [
        {'SubnetId': 'subnet-123', 'AvailabilityZone': 'eu-north-1a'}
    ]}
    ssm.get_parameter.return_value = {'Parameter': {'Value': 'ami-123'}}
    ec2.describe_images.return_value = {'Images': [{'RootDeviceName': '/dev/sda1'}]}
    ec2.create_security_group.side_effect = aws_error(
        'DryRunOperation', 'CreateSecurityGroup')
    ec2.run_instances.side_effect = aws_error(
        ('DryRunOperation' if result == 'allowed' else
         'UnauthorizedOperation' if result == 'blocked' else 'RequestLimitExceeded'),
        'RunInstances')
    return ec2, ssm


def test_scp_denied_describe_vpcs_not_shown_as_allowed():
    ec2, ssm = fake_region()
    ec2.describe_vpcs.side_effect = aws_error(
        'UnauthorizedOperation', 'DescribeVpcs',
        'explicit deny in a service control policy')
    assert launch_regions._probe_region(ec2, ssm) == 'blocked'
    ec2.create_security_group.assert_not_called()
    ec2.run_instances.assert_not_called()


def test_positive_dryruns_are_required_for_launchable_region():
    ec2, ssm = fake_region('allowed')
    assert launch_regions._probe_region(ec2, ssm) == 'allowed'
    assert ec2.create_security_group.call_args.kwargs['DryRun'] is True
    assert ec2.run_instances.call_args.kwargs['DryRun'] is True
    assert ec2.run_instances.call_args.kwargs['ImageId'] == 'ami-123'
    assert ssm.get_parameter.called
    ec2.create_key_pair.assert_not_called()


def test_incomplete_preflight_is_never_treated_as_permission():
    ec2, ssm = fake_region('unknown')
    assert launch_regions._probe_region(ec2, ssm) == 'unknown'
    ec2, ssm = fake_region('allowed')
    ec2.create_security_group.side_effect = aws_error('AccessDenied', 'CreateSecurityGroup')
    assert launch_regions._probe_region(ec2, ssm) == 'blocked'
    ec2.run_instances.assert_not_called()


def test_accounts_are_scanned_separately_and_denied_regions_hidden(monkeypatch):
    monkeypatch.setattr(launch_regions, 'region_catalog', lambda session: (
        ['eu-north-1', 'us-east-1', 'eu-west-1'], ['me-central-1']
    ))

    def session_for(allowed_regions):
        session = Mock()
        regions = {}
        for region in ['eu-north-1', 'us-east-1', 'eu-west-1']:
            ec2, ssm = fake_region(
                'allowed' if region in allowed_regions else 'blocked')
            regions[(region, 'ec2')] = ec2
            regions[(region, 'ssm')] = ssm
        session.client.side_effect = lambda kind, region_name, config: regions[(region_name, kind)]
        return session, regions

    stockholm, stockholm_clients = session_for({'eu-north-1'})
    allowed, blocked, unknown, inactive = launch_regions.find_launchable_regions(stockholm)
    assert allowed == ['eu-north-1']
    assert blocked == ['eu-west-1', 'us-east-1']
    assert unknown == []
    assert inactive == ['me-central-1']
    for (region, kind), client in stockholm_clients.items():
        if kind == 'ec2':
            client.create_security_group.assert_called_once()
            assert client.create_security_group.call_args.kwargs['DryRun'] is True
    virginia, _ = session_for({'us-east-1'})
    assert launch_regions.find_launchable_regions(virginia)[0] == ['us-east-1']


def test_only_positive_dryrun_operation_is_allowed():
    ec2, ssm = fake_region('allowed')
    ec2.create_security_group.side_effect = None
    ec2.create_security_group.return_value = {'GroupId':'sg-SHOULD-NOT-BE-CREATED'}
    assert launch_regions._probe_region(ec2, ssm) == 'unknown'
    ec2.run_instances.assert_not_called()


def test_missing_default_vpc_excludes_region_without_attempted_mutation():
    ec2, ssm = fake_region('allowed')
    ec2.describe_vpcs.return_value = {'Vpcs': []}
    assert launch_regions._probe_region(ec2, ssm) == 'blocked'
    ec2.run_instances.assert_not_called()
