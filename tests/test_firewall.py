from unittest.mock import Mock
import pytest
from src.firewall import (parse_port, add_port, attached_groups, rules_for_instance,
                          enable_ping, disable_ping, remove_rule, is_ssh_protecting)


def fake_session(rules=None):
    ec2=Mock()
    ec2.describe_instances.return_value={'Reservations':[{'Instances':[
        {'State':{'Name':'running'}, 'SecurityGroups':[{'GroupId':'sg-123','GroupName':'ec2-manager-test'}]}
    ]}]}
    pages=Mock(); pages.paginate.return_value=[{'SecurityGroupRules':rules or []}]
    ec2.get_paginator.return_value=pages
    session=Mock();session.client.return_value=ec2
    return session,ec2


def test_port_range_validation():
    assert parse_port('443')==(443,443)
    assert parse_port('10000-10009')==(10000,10009)
    for p in ['0','65536','500-400','1-2-3','1; echo', 'abc']:
        with pytest.raises(ValueError):parse_port(p)


def test_allow_tcp_udp_and_disallow_public_ssh():
    session,ec2=fake_session()
    add_port(session,'eu-north-1','i-123','sg-123','udp',49500,49500,'0.0.0.0/0')
    permissions=ec2.authorize_security_group_ingress.call_args.kwargs['IpPermissions'][0]
    assert permissions['FromPort']==49500 and permissions['IpProtocol']=='udp'
    with pytest.raises(ValueError,match='SSH'):
        add_port(session,'eu-north-1','i-123','sg-123','tcp',20,25,'0.0.0.0/0')
    with pytest.raises(ValueError,match='attached'):
        add_port(session,'eu-north-1','i-123','sg-other','tcp',443,443,'0.0.0.0/0')


def test_ping_toggle():
    session,ec2=fake_session()
    assert enable_ping(session,'eu-north-1','i-123','sg-123') is True
    args=ec2.authorize_security_group_ingress.call_args.kwargs
    assert args['IpPermissions'][0]['FromPort']==8
    assert args['IpPermissions'][0]['ToPort']==0
    rule={'SecurityGroupRuleId':'sgr-123','IpProtocol':'icmp','FromPort':8,'ToPort':0,
          'CidrIpv4':'0.0.0.0/0','IsEgress':False}
    session,ec2=fake_session([rule])
    assert enable_ping(session,'eu-north-1','i-123','sg-123') is False
    assert disable_ping(session,'eu-north-1','i-123','sg-123')==1
    ec2.revoke_security_group_ingress.assert_called_once_with(GroupId='sg-123',SecurityGroupRuleIds=['sgr-123'])


def test_remove_rule_protects_ssh_and_checks_instance_group():
    ssh_rule={'SecurityGroupRuleId':'sgr-ssh','IpProtocol':'tcp','FromPort':22,'ToPort':22,
              'CidrIpv4':'0.0.0.0/0','IsEgress':False}
    udp_rule={'SecurityGroupRuleId':'sgr-udp','IpProtocol':'udp','FromPort':49500,'ToPort':49500,
              'CidrIpv4':'0.0.0.0/0','IsEgress':False}
    assert is_ssh_protecting(ssh_rule)
    assert is_ssh_protecting({'IpProtocol':'-1'})
    session,ec2=fake_session([ssh_rule,udp_rule])
    with pytest.raises(ValueError,match='SSH-protecting'):
        remove_rule(session,'eu-north-1','i-123','sg-123','sgr-ssh')
    assert not ec2.revoke_security_group_ingress.called
    assert remove_rule(session,'eu-north-1','i-123','sg-123','sgr-udp').startswith('UDP')
    ec2.revoke_security_group_ingress.assert_called_once_with(GroupId='sg-123',SecurityGroupRuleIds=['sgr-udp'])


def test_egress_not_exposed_for_deletion():
    session,ec2=fake_session([{'SecurityGroupRuleId':'sgr-egress','IsEgress':True}])
    assert rules_for_instance(session,'eu-north-1','i-123','sg-123')==[]
