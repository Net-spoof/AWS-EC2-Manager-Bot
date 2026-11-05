"""No live AWS calls: verify OS discovery, guarded launch and pricing modes."""
from unittest.mock import Mock
import pytest

from src.os_catalog import OS_CATALOG, resolve_image, supports_password, os_label, is_windows
from src.aws_api import create_instance
from src.pricing import quote_on_demand


def fake_ec2_session(image, name='ami-0123456789abcdef0'):
    ec2=Mock()
    ec2.describe_images.return_value={'Images':[image]}
    ec2.describe_vpcs.return_value={'Vpcs':[{'VpcId':'vpc-001'}]}
    ec2.describe_subnets.return_value={'Subnets':[{'SubnetId':'subnet-001','AvailabilityZone':'eu-north-1a'}]}
    ec2.create_security_group.return_value={'GroupId':'sg-001'}
    ec2.create_key_pair.return_value={'KeyMaterial':'TEST_PRIVATE_KEY'}
    ec2.run_instances.return_value={'Instances':[{'InstanceId':'i-00000000000000001'}]}
    ssm=Mock()
    ssm.get_parameter.return_value={'Parameter':{'Value':name}}
    sess=Mock()
    sess.client.side_effect=lambda service,**kwargs: {'ec2':ec2,'ssm':ssm}[service]
    return sess,ec2,ssm


def win_image():
    return {'ImageId':'ami-0123456789abcdef0','Name':'Windows_Server-2025-English-Full-Base',
            'OwnerId':'801119661308', 'Architecture':'x86_64','RootDeviceType':'ebs',
            'RootDeviceName':'/dev/sda1', 'Platform':'windows','State':'available',
            'BlockDeviceMappings':[{'DeviceName':'/dev/sda1','Ebs':{'VolumeSize':30}}]}


def test_all_os_families_have_entry_and_versions():
    for family in ('ubuntu','debian','amazon','windows','rhel','suse','rocky','custom'):
        assert family in OS_CATALOG
    assert supports_password('ubuntu')
    assert not supports_password('windows')
    assert is_windows('windows')
    assert '2025' in os_label('windows','2025')


def test_resolves_official_windows_ami_and_rdp_launch():
    session,ec2,ssm=fake_ec2_session(win_image())
    image=resolve_image(session,'eu-north-1','windows','2025')
    assert image['platform']=='windows' and image['minimum_disk']==30
    assert 'ami-windows-latest' in ssm.get_parameter.call_args.kwargs['Name']
    result=create_instance(session,'eu-north-1','windows-test','2025','t3.medium',40,
                           '198.51.100.15/32','key',os_id='windows')
    assert result['platform']=='windows' and result['user']=='Administrator'
    args=ec2.authorize_security_group_ingress.call_args.kwargs['IpPermissions'][0]
    assert args['FromPort']==3389 and args['ToPort']==3389
    assert 'UserData' not in ec2.run_instances.call_args.kwargs
    assert ec2.run_instances.call_args.kwargs['KeyName'].startswith('ec2-manager-')


def test_windows_rejects_password_and_low_memory_before_launch():
    sess,ec2,_=fake_ec2_session(win_image())
    with pytest.raises(ValueError,match='کلید'):
        create_instance(sess,'eu-north-1','bad','2025','t3.medium',40,'198.51.100.15/32','password','windows')
    with pytest.raises(ValueError,match='۴ گیگابایت'):
        create_instance(sess,'eu-north-1','bad','2025','t3.small',40,'198.51.100.15/32','key','windows')
    assert not ec2.run_instances.called


def test_custom_image_rejects_mismatch_arch_and_password():
    image=win_image()
    image['Architecture']='arm64'
    sess,ec2,_=fake_ec2_session(image)
    with pytest.raises(ValueError,match='x86_64'):
        resolve_image(sess,'eu-north-1','custom','custom','ami-0123456789abcdef0')
    with pytest.raises(ValueError,match='شناسه AMI'):
        resolve_image(sess,'eu-north-1','custom','custom','ami-bad')


def test_debian_publisher_latest_and_ssh_user():
    sess,ec2,_=fake_ec2_session({'Architecture':'x86_64','RootDeviceType':'ebs','OwnerId':'136693071363',
                                'Name':'debian-13-amd64-20261021-2638','ImageId':'ami-0123456789abcdef0'})
    # First DescribeImages lookup returns list of latest from the known Debian owner;
    # second resolves that exact image.
    found=resolve_image(sess,'eu-north-1','debian','13')
    assert found['user']=='admin'
    assert ec2.describe_images.call_args_list[0].kwargs['Owners']==['136693071363']


def test_bot_windows_type_buttons_exclude_micro_and_small():
    pytest.importorskip('telegram')
    from src.bot import instance_type_keyboard
    rows=instance_type_keyboard({'os_id':'windows'}).inline_keyboard
    names=[btn.text for row in rows for btn in row]
    assert any('t3.medium' in name for name in names)
    assert not any('t3.micro' in name or 't3.small' in name for name in names)
    assert all(len(row)==1 for row in rows)


def test_pricing_rejects_custom_without_inventing_licensed_rate():
    with pytest.raises(ValueError,match='AWS'):
        quote_on_demand(Mock(),'eu-north-1','t3.medium',40,'custom')


def test_ami_compatibility_rules_are_enforced_before_launch():
    from src.os_catalog import check_ami_instance_type
    check_ami_instance_type(None,'t3.small')
    check_ami_instance_type({'SupportedInstanceTypes':[{'InstanceType':'t3.*'}]},'t3.small')
    with pytest.raises(ValueError,match='پشتیبانی'):
        check_ami_instance_type({'SupportedInstanceTypes':[{'InstanceType':'m5.large'}]},'t3.small')
    with pytest.raises(ValueError,match='پشتیبانی'):
        check_ami_instance_type({'UnsupportedInstanceTypes':[{'InstanceType':'t3.*'}]},'t3.small')
    image=win_image()
    image['InstanceTypeSpecification']={'SupportedInstanceTypes':[{'InstanceType':'m5.large'}]}
    sess,ec2,_=fake_ec2_session(image)
    with pytest.raises(ValueError,match='پشتیبانی'):
        create_instance(sess,'eu-north-1','vm','2025','t3.medium',40,
                        '198.51.100.15/32','key',os_id='windows')
    ec2.create_security_group.assert_not_called()
