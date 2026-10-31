import json
import re
from pathlib import Path
import pytest

from cryptography.fernet import Fernet
from src.aws_api import valid_alias, validate_cidr, cloud_init_password, make_password, UBUNTU, TYPES
from src.storage import Store


def test_alias_and_cidr():
    assert valid_alias('aws-01')
    assert not valid_alias('../bad')
    assert not valid_alias('a')
    assert validate_cidr('203.0.113.5') == '203.0.113.5/32'
    assert validate_cidr('198.51.100.20/24') == '198.51.100.0/24'
    with pytest.raises(ValueError): validate_cidr('::/0')


def test_cloudinit_only_has_password_hash():
    password='VeryStrongRandomPassword#9420938'
    config=cloud_init_password(password)
    assert config.startswith('#cloud-config\n')
    assert password not in config
    assert 'ssh_pwauth: true' in config
    assert '$6$' in config
    assert 'type: hash' in config


def test_password_randomness_shape():
    p1=make_password()
    p2=make_password()
    assert p1 != p2
    assert len(p1)==26
    assert len(p2)==26


def test_encrypted_account_store(tmp_path):
    key=Fernet.generate_key().decode()
    path=tmp_path/'accounts.sqlite3'
    store=Store(str(path),key)
    account_id=store.add_account('dev','keys',json.dumps({'access_key':'EXAMPLE','secret_key':'TOPSECRET'}),'123456789012')
    assert b'TOPSECRET' not in path.read_bytes()
    account=store.account(account_id)
    assert json.loads(account['payload'])['secret_key']=='TOPSECRET'
    assert store.accounts()[0]['alias']=='dev'
    store.log(account_id,'create','eu-central-1','i-1234567890')
    assert store.recent()[0]['operation']=='create'
    store.remove_account(account_id)
    assert not store.accounts()


def test_ubuntu_parameters_and_types():
    assert set(UBUNTU)=={'22.04','24.04','26.04'}
    assert all(t.startswith(('t3.','t3a.')) for t in TYPES)


def test_create_ec2_using_fake_api(monkeypatch):
    from unittest.mock import Mock
    from src.aws_api import create_instance

    ec2=Mock()
    ssm=Mock()
    ec2.describe_vpcs.return_value={'Vpcs':[{'VpcId':'vpc-001'}]}
    ec2.describe_subnets.return_value={'Subnets':[{'SubnetId':'subnet-001','AvailabilityZone':'eu-central-1a'}]}
    ec2.describe_images.return_value={'Images':[{'RootDeviceName':'/dev/sda1','BlockDeviceMappings':[
        {'DeviceName':'/dev/sda1','Ebs':{'VolumeSize':8}}]}]}
    ec2.create_security_group.return_value={'GroupId':'sg-001'}
    ec2.create_key_pair.return_value={'KeyMaterial':'FAKE_PRIVATE_KEY_MATERIAL'}
    ec2.run_instances.return_value={'Instances':[{'InstanceId':'i-00000000000000001'}]}
    ssm.get_parameter.return_value={'Parameter':{'Value':'ami-001'}}
    sess=Mock()
    sess.client.side_effect=lambda name,**kwargs: {'ec2':ec2,'ssm':ssm}[name]
    result=create_instance(sess,'eu-central-1','test-vm','24.04','t3.micro',20,'203.0.113.1/32','key')
    assert result['id']=='i-00000000000000001'
    assert result['pem']=='FAKE_PRIVATE_KEY_MATERIAL'
    kwargs=ec2.run_instances.call_args.kwargs
    assert kwargs['NetworkInterfaces'][0]['AssociatePublicIpAddress'] is True
    assert kwargs['MetadataOptions']['HttpTokens']=='required'
    assert kwargs['BlockDeviceMappings'][0]['Ebs']['Encrypted'] is True
    assert kwargs['ClientToken']
    assert kwargs['ImageId']=='ami-001'
    assert kwargs['KeyName'].startswith('ec2-manager-')
    ec2.authorize_security_group_ingress.assert_called_once()


def test_failed_launch_cleans_managed_resources():
    from unittest.mock import Mock
    from src.aws_api import create_instance
    ec2=Mock()
    ssm=Mock()
    ec2.describe_vpcs.return_value={'Vpcs':[{'VpcId':'vpc-001'}]}
    ec2.describe_subnets.return_value={'Subnets':[{'SubnetId':'subnet-001','AvailabilityZone':'eu-central-1a'}]}
    ec2.describe_images.return_value={'Images':[{'RootDeviceName':'/dev/sda1'}]}
    ec2.create_security_group.return_value={'GroupId':'sg-001'}
    ec2.create_key_pair.return_value={'KeyMaterial':'FAKE_PRIVATE_KEY'}
    ec2.run_instances.side_effect=RuntimeError('API refused request')
    ssm.get_parameter.return_value={'Parameter':{'Value':'ami-001'}}
    sess=Mock()
    sess.client.side_effect=lambda name,**kwargs:{'ec2':ec2,'ssm':ssm}[name]
    with pytest.raises(RuntimeError):
        create_instance(sess,'eu-central-1','test-vm','24.04','t3.micro',20,'203.0.113.0/24','key')
    ec2.delete_security_group.assert_called_once_with(GroupId='sg-001')
    ec2.delete_key_pair.assert_called_once()
