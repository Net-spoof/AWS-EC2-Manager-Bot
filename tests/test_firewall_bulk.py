"""Tests for EC2 bulk ingress controls (all AWS calls mocked)."""
from unittest.mock import Mock

import pytest

from src.firewall import (
    add_port_batch, close_bulk_ports, group_instance_count, managed_bulk_rules,
    open_all_ports, parse_port_list,
)


def fake_session(rules=None, group='sg-123'):
    ec2 = Mock()
    ec2.describe_instances.return_value = {
        'Reservations': [{'Instances': [
            {'State': {'Name': 'running'}, 'InstanceId': 'i-123',
             'SecurityGroups': [{'GroupId': group, 'GroupName': 'test'}]}
        ]}]
    }

    def paginator(name):
        result = Mock()
        if name == 'describe_security_group_rules':
            result.paginate.return_value = [{'SecurityGroupRules': rules or []}]
        elif name == 'describe_instances':
            result.paginate.return_value = [{'Reservations': [
                {'Instances': [{'InstanceId': 'i-123', 'State': {'Name': 'running'}}]},
                {'Instances': [{'InstanceId': 'i-456', 'State': {'Name': 'stopped'}}]},
            ]}]
        else:
            raise AssertionError(name)
        return result

    ec2.get_paginator.side_effect = paginator
    session = Mock()
    session.client.return_value = ec2
    return session, ec2


ARGS = ('eu-north-1', 'i-123', 'sg-123')


def test_parse_list_bilingual_separators_and_dedup():
    assert parse_port_list('80,443، 8080-8082\\n443') == [
        (80, 80), (443, 443), (8080, 8082)
    ]
    for value in ('', '0', '65536', '100-99', '80;443',
                  '1-2-3', '22, 80;id', ','.join(str(x) for x in range(1, 22))):
        with pytest.raises(ValueError):
            parse_port_list(value)


def test_open_all_private_creates_two_rules_only():
    session, ec2 = fake_session()
    count = open_all_ports(session, *ARGS, '198.51.100.14/32')
    assert count == 2
    call = ec2.authorize_security_group_ingress.call_args.kwargs
    assert call['GroupId'] == 'sg-123'
    rules = call['IpPermissions']
    assert {(r['IpProtocol'], r['FromPort'], r['ToPort']) for r in rules} == {
        ('tcp', 1, 65535), ('udp', 1, 65535)
    }
    assert all(r['IpRanges'][0]['CidrIp'] == '198.51.100.14/32' for r in rules)
    assert all(r['IpRanges'][0]['Description'] == 'AWS-EC2-Manager-Bot bulk' for r in rules)


def test_public_all_excludes_ssh_rdp_and_requires_confirmation_in_ui():
    session, ec2 = fake_session()
    assert open_all_ports(session, *ARGS, '0.0.0.0/0') == 5
    rules = ec2.authorize_security_group_ingress.call_args.kwargs['IpPermissions']
    assert len(rules) == 5
    for rule in rules:
        start, end = rule['FromPort'], rule['ToPort']
        if rule['IpProtocol'] == 'tcp':
            assert not (start <= 22 <= end or start <= 3389 <= end)
        if rule['IpProtocol'] == 'udp':
            assert not start <= 3389 <= end


def test_multi_ports_skips_existing_and_creates_only_missing_rules():
    existing = [{
        'SecurityGroupRuleId': 'sgr-old', 'IpProtocol': 'tcp',
        'FromPort': 443, 'ToPort': 443, 'CidrIpv4': '198.51.100.14/32',
        'IsEgress': False,
    }]
    session, ec2 = fake_session(existing)
    count = add_port_batch(session, *ARGS, ['tcp'], [(80, 80), (443, 443)], '198.51.100.14')
    assert count == 1
    perms = ec2.authorize_security_group_ingress.call_args.kwargs['IpPermissions']
    assert len(perms) == 1 and perms[0]['FromPort'] == 80


def test_all_exact_existing_rules_is_noop():
    existing = [
        {'IpProtocol': proto, 'FromPort': 1, 'ToPort': 65535,
         'CidrIpv4': '198.51.100.14/32', 'IsEgress': False}
        for proto in ('tcp', 'udp')
    ]
    session, ec2 = fake_session(existing)
    assert open_all_ports(session, *ARGS, '198.51.100.14/32') == 0
    ec2.authorize_security_group_ingress.assert_not_called()


def test_no_public_ssh_rdp_even_with_bulk_ports():
    session, ec2 = fake_session()
    with pytest.raises(ValueError, match='SSH/RDP'):
        add_port_batch(session, *ARGS, ['tcp'], [(20, 25)], '0.0.0.0/0')
    with pytest.raises(ValueError, match='SSH/RDP'):
        add_port_batch(session, *ARGS, ['udp'], [(3389, 3389)], '0.0.0.0/0')
    ec2.authorize_security_group_ingress.assert_not_called()


def test_group_must_be_attached_to_selected_instance():
    session, ec2 = fake_session()
    with pytest.raises(ValueError, match='attached'):
        open_all_ports(session, 'eu-north-1', 'i-123', 'sg-other', '198.51.100.14/32')
    ec2.authorize_security_group_ingress.assert_not_called()


def test_close_only_marked_bulk_rules():
    rules = [
        {'SecurityGroupRuleId': 'sgr-bulk', 'Description': 'AWS-EC2-Manager-Bot bulk',
         'IpProtocol': 'tcp', 'FromPort': 1, 'ToPort': 65535, 'IsEgress': False},
        {'SecurityGroupRuleId': 'sgr-normal', 'Description': 'SSH access',
         'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IsEgress': False},
        {'SecurityGroupRuleId': 'sgr-other', 'Description': 'Other service',
         'IpProtocol': 'udp', 'FromPort': 49500, 'ToPort': 49500, 'IsEgress': False},
    ]
    session, ec2 = fake_session(rules)
    assert len(managed_bulk_rules(rules)) == 1
    assert close_bulk_ports(session, *ARGS) == 1
    ec2.revoke_security_group_ingress.assert_called_once_with(
        GroupId='sg-123', SecurityGroupRuleIds=['sgr-bulk']
    )


def test_close_none_is_safe_noop():
    session, ec2 = fake_session()
    assert close_bulk_ports(session, *ARGS) == 0
    ec2.revoke_security_group_ingress.assert_not_called()


def test_group_impact_count_detects_shared_instances():
    session, _ = fake_session()
    assert group_instance_count(session, *ARGS) == 2
