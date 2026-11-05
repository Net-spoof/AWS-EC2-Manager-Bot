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

def test_root_login_cloudinit_keeps_only_hash_and_recovery_user():
    password='SuperStrongRootPassword#2026!'
    config=cloud_init_password(password, root_login=True)
    assert password not in config
    assert config.startswith('#cloud-config\n')
    assert 'ssh_pwauth: true' in config
    assert 'disable_root: false' in config
    assert 'name: root' in config
    assert 'name: ubuntu' in config
    assert 'PermitRootLogin yes' in config
    assert 'PasswordAuthentication yes' in config
    assert '00-aws-ec2-manager-root.conf' in config
    assert 'systemctl reload ssh' in config
    assert config.count('type: hash') == 2
    assert '$6$rounds=120000$' in config


def test_default_cloudinit_does_not_enable_root():
    config=cloud_init_password('NotARealProductionPassword123!')
    assert 'PermitRootLogin yes' not in config
    assert 'name: root' not in config
    assert 'disable_root: false' not in config


def test_root_mode_in_create_instance(monkeypatch):
    from unittest.mock import Mock
    from src.aws_api import create_instance
    ec2=Mock()
    ssm=Mock()
    ec2.describe_vpcs.return_value={'Vpcs':[{'VpcId':'vpc-001'}]}
    ec2.describe_subnets.return_value={'Subnets':[{'SubnetId':'subnet-001','AvailabilityZone':'eu-central-1a'}]}
    ec2.describe_images.return_value={'Images':[{'RootDeviceName':'/dev/sda1', 'Architecture':'x86_64',
       'RootDeviceType':'ebs','OwnerId':'099720109477','State':'available','BlockDeviceMappings':[]}]}
    ec2.create_security_group.return_value={'GroupId':'sg-001'}
    ec2.run_instances.return_value={'Instances':[{'InstanceId':'i-00000000000000001'}]}
    ssm.get_parameter.return_value={'Parameter':{'Value':'ami-001'} }
    sess=Mock()
    sess.client.side_effect=lambda name,**kwargs: {'ec2':ec2,'ssm':ssm}[name]
    result=create_instance(sess,'eu-central-1','root-test','24.04','t3.micro',20,'203.0.113.1/32','root_password')
    assert result['user']=='root'
    assert result['password'] and len(result['password'])==26
    assert result['pem'] is None
    kwargs=ec2.run_instances.call_args.kwargs
    assert 'KeyName' not in kwargs
    assert 'PermitRootLogin yes' in kwargs['UserData']
    assert result['password'] not in kwargs['UserData']
    assert 'name: ubuntu' in kwargs['UserData']
    assert 'name: root' in kwargs['UserData']
    assert kwargs['NetworkInterfaces'][0]['AssociatePublicIpAddress'] is True


def test_root_password_rejected_for_non_ubuntu():
    from unittest.mock import Mock
    from src.aws_api import create_instance
    sess=Mock()
    with pytest.raises(ValueError, match='Ubuntu'):
        create_instance(sess,'eu-central-1','root-test','12','t3.micro',20,'203.0.113.1/32','root_password','debian')
    assert not sess.client.called



def _launch_session_with_denial(operation):
    from unittest.mock import Mock
    from botocore.exceptions import ClientError

    ec2 = Mock()
    ssm = Mock()
    ec2.describe_vpcs.return_value={'Vpcs':[{'VpcId':'vpc-001'}]}
    ec2.describe_subnets.return_value={'Subnets':[{'SubnetId':'subnet-001','AvailabilityZone':'eu-north-1a'}]}
    ec2.describe_images.return_value={'Images':[{'RootDeviceName':'/dev/sda1', 'BlockDeviceMappings':[]}]}
    ec2.create_security_group.return_value={'GroupId':'sg-001'}
    ec2.create_key_pair.return_value={'KeyMaterial':'FAKE'}
    ssm.get_parameter.return_value={'Parameter':{'Value':'ami-001'}}
    err=ClientError({'Error':{'Code':'UnauthorizedOperation',
                             'Message':'You are not authorized to perform this operation. '
                             'Encoded authorization failure message: SECRET-ENCODED-STRING'}},operation)
    import re
    method = re.sub(r'(?<!^)(?=[A-Z])', '_', operation).lower()
    getattr(ec2, method).side_effect = err
    session=Mock()
    session.client.side_effect=lambda name,**kwargs:{'ec2':ec2, 'ssm':ssm}[name]
    return session,ec2


def test_launch_denial_identifies_security_group_action_without_leaking_aws_encoded_message():
    from src.aws_api import create_instance
    from src.launch_errors import EC2LaunchPermissionError, display_launch_denial
    session, ec2 = _launch_session_with_denial('CreateSecurityGroup')
    with pytest.raises(EC2LaunchPermissionError) as e:
        create_instance(session,'eu-north-1','test-server','24.04','t3.small',20,'203.0.113.5/32','password')
    text=display_launch_denial(e.value)
    assert 'ec2:CreateSecurityGroup' in text
    assert 'eu-north-1' in text
    assert 'SECRET-ENCODED-STRING' not in text
    ec2.run_instances.assert_not_called()


def test_launch_denial_in_runinstances_reports_step_and_keeps_cleanup():
    from src.aws_api import create_instance
    from src.launch_errors import EC2LaunchPermissionError, display_launch_denial
    session, ec2 = _launch_session_with_denial('RunInstances')
    with pytest.raises(EC2LaunchPermissionError) as e:
        create_instance(session,'eu-north-1','test-server','24.04','t3.small',20,'203.0.113.5/32','key')
    assert 'ec2:RunInstances' in display_launch_denial(e.value)
    ec2.delete_security_group.assert_called_once_with(GroupId='sg-001')
    ec2.delete_key_pair.assert_called_once()


def test_scp_hint_is_based_on_aws_message_not_inferred():
    from botocore.exceptions import ClientError
    from src.launch_errors import transform_launch_denial, display_launch_denial
    def err(message):
        return ClientError({'Error':{'Code':'UnauthorizedOperation','Message':message}},'RunInstances')
    a=transform_launch_denial(err('because of an explicit deny in a service control policy'),
                             'ec2:RunInstances','eu-north-1')
    b=transform_launch_denial(err('generic denied: ENCODED-SECRET'),
                             'ec2:RunInstances','eu-north-1')
    assert a.deny_type=='SCP'
    assert b.deny_type is None
    assert 'علت دقیق' in display_launch_denial(b)
    assert 'ENCODED-SECRET' not in display_launch_denial(b)


def test_invalid_parameter_combination_shows_aws_message_safely():
    from botocore.exceptions import ClientError
    from src.launch_errors import transform_launch_parameter_error,display_launch_parameter_error
    bad=ClientError({'Error':{
        'Code':'InvalidParameterCombination',
        'Message':'This AMI does not support the specified instance type.'
    }},'RunInstances')
    exc=transform_launch_parameter_error(bad,'ec2:RunInstances','us-east-1')
    message=display_launch_parameter_error(exc)
    assert 'RunInstances' in message and 'us-east-1' in message
    assert 'This AMI does not support' in message
    secret=ClientError({'Error':{
        'Code':'InvalidParameterCombination',
        'Message':'UserData password=PRIVATE_SECRET'
    }},'RunInstances')
    assert 'PRIVATE_SECRET' not in display_launch_parameter_error(
        transform_launch_parameter_error(secret,'ec2:RunInstances','us-east-1'))
