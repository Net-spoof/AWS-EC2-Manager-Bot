"""AWS operations. All cloud calls happen from worker threads in bot.py."""
import datetime as dt
import ipaddress
import json
import re
import secrets
import subprocess
import string
import uuid
import boto3
from botocore.config import Config

AWS_CONFIG = Config(connect_timeout=8, read_timeout=25, retries={'max_attempts': 3, 'mode':'standard'})
UBUNTU = {'22.04': ('jammy', 'ebs-gp2'), '24.04':('noble','ebs-gp3'), '26.04':('resolute','ebs-gp3')}
TYPES = ('t3.micro','t3.small','t3.medium','t3.large','t3.xlarge','t3.2xlarge','t3a.micro','t3a.small','t3a.medium','t3a.large')
# Compatibility list; actual availability comes from AWS DescribeRegions.
REGIONS = ('eu-central-1','eu-central-2','eu-west-1','eu-west-2','eu-west-3','eu-north-1','eu-south-1','eu-south-2',
           'us-east-1','us-east-2','us-west-1','us-west-2','ca-central-1','ap-south-1','ap-south-2',
           'ap-southeast-1','ap-southeast-2','ap-northeast-1','ap-northeast-2','ap-northeast-3','me-central-1','me-south-1',
           'af-south-1','ap-east-1','ap-east-2','ap-southeast-3','ap-southeast-4','ap-southeast-5','ap-southeast-6',
           'ap-southeast-7','ca-west-1','il-central-1','mx-central-1','sa-east-1')
REGION_PATTERN = re.compile(r'^[a-z]{2}(?:-[a-z]+)+-[1-9][0-9]*

def valid_alias(text):
    return bool(re.fullmatch(r'[A-Za-z0-9_-]{2,32}', text))


def validate_cidr(text):
    network = ipaddress.ip_network(text, strict=False)
    if network.version != 4:
        raise ValueError('Only IPv4 CIDRs are supported')
    return str(network)


def session_for_account(account):
    """Access keys encrypted at rest, or assume cross-account role from host credentials."""
    payload = json.loads(account['payload'])
    if account['kind'] == 'keys':
        return boto3.Session(aws_access_key_id=payload['access_key'], aws_secret_access_key=payload['secret_key'],
                             aws_session_token=payload.get('session_token'), region_name='us-east-1')
    # Uses the standard AWS credential provider chain on the bot's host.
    sts = boto3.Session().client('sts', config=AWS_CONFIG)
    response = sts.assume_role(RoleArn=payload['role_arn'], RoleSessionName='EC2ManagerBot')
    temp = response['Credentials']
    return boto3.Session(aws_access_key_id=temp['AccessKeyId'], aws_secret_access_key=temp['SecretAccessKey'],
                         aws_session_token=temp['SessionToken'], region_name='us-east-1')


def validate_account(kind, payload):
    account = {'kind':kind,'payload':json.dumps(payload)}
    return session_for_account(account).client('sts',config=AWS_CONFIG).get_caller_identity()['Account']


def region_catalog(session):
    """Use the account's AWS Region opt-in status rather than a hardcoded list."""
    result = session.client('ec2', region_name='us-east-1', config=AWS_CONFIG).describe_regions(AllRegions=True)
    enabled, disabled = [], []
    for item in result.get('Regions', []):
        region = item.get('RegionName', '')
        if not valid_region_id(region):
            continue
        status = item.get('OptInStatus', '')
        if status in ('opt-in-not-required', 'opted-in'):
            enabled.append(region)
        else:
            disabled.append(region)
    return sorted(set(enabled)), sorted(set(disabled))


def available_regions(session):
    return region_catalog(session)[0]

def resolve_ubuntu_ami(session, region, release):
    if release not in UBUNTU:
        raise ValueError('Unsupported Ubuntu version')
    codename, volume = UBUNTU[release]
    name = f'/aws/service/canonical/ubuntu/server/{codename}/stable/current/amd64/hvm/{volume}/ami-id'
    ssm = session.client('ssm',region_name=region,config=AWS_CONFIG)
    return ssm.get_parameter(Name=name)['Parameter']['Value']


def ensure_default_vpc_subnet(ec2):
    vpcs = ec2.describe_vpcs(Filters=[{'Name':'is-default','Values':['true']}])['Vpcs']
    if not vpcs:
        raise ValueError('No default VPC in this region. Create/restore one first in AWS.')
    vpc_id = vpcs[0]['VpcId']
    subnets = ec2.describe_subnets(Filters=[{'Name':'vpc-id','Values':[vpc_id]},
                                          {'Name':'default-for-az','Values':['true']}])['Subnets']
    if not subnets:
        raise ValueError('Default VPC has no default subnet.')
    return vpc_id, sorted(subnets,key=lambda subnet:subnet['AvailabilityZone'])[0]['SubnetId']


def cloud_init_password(password):
    """Put only a one-time password HASH in userdata, never the plaintext password."""
    salt = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    result = subprocess.run(['openssl', 'passwd', '-6', '-stdin', '-salt', f'rounds=120000${salt}'],
                            input=password + '\n', text=True, capture_output=True, check=True)
    hashed = result.stdout.strip()
    if not hashed.startswith('$6$rounds=120000$'):
        raise ValueError('Unable to generate SHA-512 crypt password hash')
    return ('#cloud-config\nssh_pwauth: true\nchpasswd:\n  expire: false\n  users:\n'
            f'    - name: ubuntu\n      password: "{hashed}"\n      type: hash\n')


def make_password(length=26):
    alphabet = string.ascii_letters + string.digits + '!@#%-_+'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def create_instance(session, region, name, release, instance_type, disk_gb, ssh_cidr, access_mode):
    if not valid_region_id(region) or instance_type not in TYPES or release not in UBUNTU:
        raise ValueError('Invalid region, instance type or release')
    if not (12 <= disk_gb <= 1024):
        raise ValueError('Disk should be between 12 and 1024 GiB')
    cidr = validate_cidr(ssh_cidr)
    if access_mode not in ('password','key'):
        raise ValueError('Invalid login mode')
    ec2 = session.client('ec2',region_name=region,config=AWS_CONFIG)
    vpc, subnet = ensure_default_vpc_subnet(ec2)
    ami = resolve_ubuntu_ami(session, region, release)
    image = ec2.describe_images(ImageIds=[ami])['Images'][0]
    root_device = image.get('RootDeviceName', '/dev/sda1')
    min_disk = max(12, int(image.get('BlockDeviceMappings',[{}])[0].get('Ebs',{}).get('VolumeSize',8)))
    if disk_gb < min_disk:
        raise ValueError(f'Ubuntu image requires at least {min_disk} GiB')
    password = make_password() if access_mode == 'password' else None
    security_group = None
    key_name = None
    key_material = None
    instance_id = None
    try:
        group_name = 'ec2-manager-' + uuid.uuid4().hex[:15]
        security_group = ec2.create_security_group(GroupName=group_name,
                       Description='SSH access for AWS EC2 Manager Bot',VpcId=vpc)['GroupId']
        ec2.authorize_security_group_ingress(GroupId=security_group, IpPermissions=[{
            'IpProtocol':'tcp','FromPort':22,'ToPort':22,'IpRanges':[{'CidrIp':cidr,'Description':'SSH access'}]}])
        if access_mode == 'key':
            key_name = 'ec2-manager-' + uuid.uuid4().hex[:15]
            key_material = ec2.create_key_pair(KeyName=key_name,KeyType='rsa',KeyFormat='pem')['KeyMaterial']
        params = dict(
            ImageId=ami, InstanceType=instance_type, MinCount=1,MaxCount=1,
            ClientToken=uuid.uuid4().hex,
            NetworkInterfaces=[{'DeviceIndex':0,'SubnetId':subnet,'Groups':[security_group],
                                'AssociatePublicIpAddress':True,'DeleteOnTermination':True}],
            BlockDeviceMappings=[{'DeviceName':root_device,'Ebs':{'VolumeSize':disk_gb,'VolumeType':'gp3',
                                                               'Encrypted':True,'DeleteOnTermination':True}}],
            MetadataOptions={'HttpTokens':'required','HttpEndpoint':'enabled'},
            TagSpecifications=[{'ResourceType':'instance','Tags':[{'Key':'Name','Value':name},
                                                           {'Key':'ManagedBy','Value':'AWS-EC2-Manager-Bot'}]}]
        )
        if key_name:
            params['KeyName'] = key_name
        if password:
            params['UserData'] = cloud_init_password(password)
        instance_id = ec2.run_instances(**params)['Instances'][0]['InstanceId']
        return {'id':instance_id,'password':password,'pem':key_material,'key_name':key_name,'sg_id':security_group}
    except Exception:
        if instance_id is None:
            if key_name:
                try: ec2.delete_key_pair(KeyName=key_name)
                except Exception: pass
            if security_group:
                try: ec2.delete_security_group(GroupId=security_group)
                except Exception: pass
        raise


def list_instances(session, region):
    ec2 = session.client('ec2',region_name=region,config=AWS_CONFIG)
    paginator = ec2.get_paginator('describe_instances')
    rows = []
    for page in paginator.paginate(PaginationConfig={'MaxItems':100}):
        for res in page.get('Reservations',[]):
            for inst in res['Instances']:
                if inst['State']['Name']=='terminated':
                    continue
                tags = {t['Key']:t['Value'] for t in inst.get('Tags',[])}
                rows.append({'id':inst['InstanceId'],'name':tags.get('Name','Unnamed')[:60],
                             'state':inst['State']['Name'],'ip':inst.get('PublicIpAddress','—'),
                             'type':inst['InstanceType'], 'launched':str(inst.get('LaunchTime',''))})
    return sorted(rows,key=lambda r:r['launched'],reverse=True)[:100]


def instance_details(session, region, instance_id):
    ec2 = session.client('ec2',region_name=region,config=AWS_CONFIG)
    inst = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
    tags = {t['Key']:t['Value'] for t in inst.get('Tags',[])}
    return {'id':instance_id,'name':tags.get('Name','Unnamed'),'state':inst['State']['Name'],
            'ip':inst.get('PublicIpAddress','—'),'private_ip':inst.get('PrivateIpAddress','—'),
            'type':inst['InstanceType'],'key_name':inst.get('KeyName','—'),
            'zone':inst['Placement']['AvailabilityZone'],'vpc':inst.get('VpcId','—')}


def control_instance(session, region, instance_id, action):
    ec2 = session.client('ec2',region_name=region,config=AWS_CONFIG)
    if action == 'start': ec2.start_instances(InstanceIds=[instance_id])
    elif action == 'stop': ec2.stop_instances(InstanceIds=[instance_id])
    elif action == 'reboot': ec2.reboot_instances(InstanceIds=[instance_id])
    elif action == 'terminate': ec2.terminate_instances(InstanceIds=[instance_id])
    else: raise ValueError('Unsupported action')


def cpu_metric(session,region,instance_id):
    client=session.client('cloudwatch',region_name=region,config=AWS_CONFIG)
    end=dt.datetime.now(dt.timezone.utc)
    start=end-dt.timedelta(minutes=30)
    resp=client.get_metric_statistics(Namespace='AWS/EC2',MetricName='CPUUtilization',
                                     Dimensions=[{'Name':'InstanceId','Value':instance_id}],
                                     StartTime=start,EndTime=end,Period=300,Statistics=['Average'])
    points=sorted(resp.get('Datapoints',[]),key=lambda p:p['Timestamp'])
    return round(points[-1]['Average'],1) if points else None


def monthly_cost(session):
    client=session.client('ce',region_name='us-east-1',config=AWS_CONFIG)
    today=dt.datetime.now(dt.timezone.utc).date()
    start=today.replace(day=1)
    end=today+dt.timedelta(days=1)
    report=client.get_cost_and_usage(TimePeriod={'Start':start.isoformat(),'End':end.isoformat()},
                                     Granularity='MONTHLY',Metrics=['UnblendedCost'])
    cost=report['ResultsByTime'][0]['Total']['UnblendedCost']
    return {'value':cost['Amount'],'currency':cost['Unit'],'estimated':report['ResultsByTime'][0].get('Estimated',True)}
)


def valid_region_id(region):
    return isinstance(region, str) and bool(REGION_PATTERN.fullmatch(region))


def valid_alias(text):
    return bool(re.fullmatch(r'[A-Za-z0-9_-]{2,32}', text))


def validate_cidr(text):
    network = ipaddress.ip_network(text, strict=False)
    if network.version != 4:
        raise ValueError('Only IPv4 CIDRs are supported')
    return str(network)


def session_for_account(account):
    """Access keys encrypted at rest, or assume cross-account role from host credentials."""
    payload = json.loads(account['payload'])
    if account['kind'] == 'keys':
        return boto3.Session(aws_access_key_id=payload['access_key'], aws_secret_access_key=payload['secret_key'],
                             aws_session_token=payload.get('session_token'), region_name='us-east-1')
    # Uses the standard AWS credential provider chain on the bot's host.
    sts = boto3.Session().client('sts', config=AWS_CONFIG)
    response = sts.assume_role(RoleArn=payload['role_arn'], RoleSessionName='EC2ManagerBot')
    temp = response['Credentials']
    return boto3.Session(aws_access_key_id=temp['AccessKeyId'], aws_secret_access_key=temp['SecretAccessKey'],
                         aws_session_token=temp['SessionToken'], region_name='us-east-1')


def validate_account(kind, payload):
    account = {'kind':kind,'payload':json.dumps(payload)}
    return session_for_account(account).client('sts',config=AWS_CONFIG).get_caller_identity()['Account']


def available_regions(session):
    result = session.client('ec2',region_name='us-east-1',config=AWS_CONFIG).describe_regions(AllRegions=False)
    enabled = {r['RegionName'] for r in result['Regions']}
    return [r for r in REGIONS if r in enabled]


def resolve_ubuntu_ami(session, region, release):
    if release not in UBUNTU:
        raise ValueError('Unsupported Ubuntu version')
    codename, volume = UBUNTU[release]
    name = f'/aws/service/canonical/ubuntu/server/{codename}/stable/current/amd64/hvm/{volume}/ami-id'
    ssm = session.client('ssm',region_name=region,config=AWS_CONFIG)
    return ssm.get_parameter(Name=name)['Parameter']['Value']


def ensure_default_vpc_subnet(ec2):
    vpcs = ec2.describe_vpcs(Filters=[{'Name':'is-default','Values':['true']}])['Vpcs']
    if not vpcs:
        raise ValueError('No default VPC in this region. Create/restore one first in AWS.')
    vpc_id = vpcs[0]['VpcId']
    subnets = ec2.describe_subnets(Filters=[{'Name':'vpc-id','Values':[vpc_id]},
                                          {'Name':'default-for-az','Values':['true']}])['Subnets']
    if not subnets:
        raise ValueError('Default VPC has no default subnet.')
    return vpc_id, sorted(subnets,key=lambda subnet:subnet['AvailabilityZone'])[0]['SubnetId']


def cloud_init_password(password):
    """Put only a one-time password HASH in userdata, never the plaintext password."""
    salt = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    result = subprocess.run(['openssl', 'passwd', '-6', '-stdin', '-salt', f'rounds=120000${salt}'],
                            input=password + '\n', text=True, capture_output=True, check=True)
    hashed = result.stdout.strip()
    if not hashed.startswith('$6$rounds=120000$'):
        raise ValueError('Unable to generate SHA-512 crypt password hash')
    return ('#cloud-config\nssh_pwauth: true\nchpasswd:\n  expire: false\n  users:\n'
            f'    - name: ubuntu\n      password: "{hashed}"\n      type: hash\n')


def make_password(length=26):
    alphabet = string.ascii_letters + string.digits + '!@#%-_+'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def create_instance(session, region, name, release, instance_type, disk_gb, ssh_cidr, access_mode):
    if region not in REGIONS or instance_type not in TYPES or release not in UBUNTU:
        raise ValueError('Invalid region, instance type or release')
    if not (12 <= disk_gb <= 1024):
        raise ValueError('Disk should be between 12 and 1024 GiB')
    cidr = validate_cidr(ssh_cidr)
    if access_mode not in ('password','key'):
        raise ValueError('Invalid login mode')
    ec2 = session.client('ec2',region_name=region,config=AWS_CONFIG)
    vpc, subnet = ensure_default_vpc_subnet(ec2)
    ami = resolve_ubuntu_ami(session, region, release)
    image = ec2.describe_images(ImageIds=[ami])['Images'][0]
    root_device = image.get('RootDeviceName', '/dev/sda1')
    min_disk = max(12, int(image.get('BlockDeviceMappings',[{}])[0].get('Ebs',{}).get('VolumeSize',8)))
    if disk_gb < min_disk:
        raise ValueError(f'Ubuntu image requires at least {min_disk} GiB')
    password = make_password() if access_mode == 'password' else None
    security_group = None
    key_name = None
    key_material = None
    instance_id = None
    try:
        group_name = 'ec2-manager-' + uuid.uuid4().hex[:15]
        security_group = ec2.create_security_group(GroupName=group_name,
                       Description='SSH access for AWS EC2 Manager Bot',VpcId=vpc)['GroupId']
        ec2.authorize_security_group_ingress(GroupId=security_group, IpPermissions=[{
            'IpProtocol':'tcp','FromPort':22,'ToPort':22,'IpRanges':[{'CidrIp':cidr,'Description':'SSH access'}]}])
        if access_mode == 'key':
            key_name = 'ec2-manager-' + uuid.uuid4().hex[:15]
            key_material = ec2.create_key_pair(KeyName=key_name,KeyType='rsa',KeyFormat='pem')['KeyMaterial']
        params = dict(
            ImageId=ami, InstanceType=instance_type, MinCount=1,MaxCount=1,
            ClientToken=uuid.uuid4().hex,
            NetworkInterfaces=[{'DeviceIndex':0,'SubnetId':subnet,'Groups':[security_group],
                                'AssociatePublicIpAddress':True,'DeleteOnTermination':True}],
            BlockDeviceMappings=[{'DeviceName':root_device,'Ebs':{'VolumeSize':disk_gb,'VolumeType':'gp3',
                                                               'Encrypted':True,'DeleteOnTermination':True}}],
            MetadataOptions={'HttpTokens':'required','HttpEndpoint':'enabled'},
            TagSpecifications=[{'ResourceType':'instance','Tags':[{'Key':'Name','Value':name},
                                                           {'Key':'ManagedBy','Value':'AWS-EC2-Manager-Bot'}]}]
        )
        if key_name:
            params['KeyName'] = key_name
        if password:
            params['UserData'] = cloud_init_password(password)
        instance_id = ec2.run_instances(**params)['Instances'][0]['InstanceId']
        return {'id':instance_id,'password':password,'pem':key_material,'key_name':key_name,'sg_id':security_group}
    except Exception:
        if instance_id is None:
            if key_name:
                try: ec2.delete_key_pair(KeyName=key_name)
                except Exception: pass
            if security_group:
                try: ec2.delete_security_group(GroupId=security_group)
                except Exception: pass
        raise


def list_instances(session, region):
    ec2 = session.client('ec2',region_name=region,config=AWS_CONFIG)
    paginator = ec2.get_paginator('describe_instances')
    rows = []
    for page in paginator.paginate(PaginationConfig={'MaxItems':100}):
        for res in page.get('Reservations',[]):
            for inst in res['Instances']:
                if inst['State']['Name']=='terminated':
                    continue
                tags = {t['Key']:t['Value'] for t in inst.get('Tags',[])}
                rows.append({'id':inst['InstanceId'],'name':tags.get('Name','Unnamed')[:60],
                             'state':inst['State']['Name'],'ip':inst.get('PublicIpAddress','—'),
                             'type':inst['InstanceType'], 'launched':str(inst.get('LaunchTime',''))})
    return sorted(rows,key=lambda r:r['launched'],reverse=True)[:100]


def instance_details(session, region, instance_id):
    ec2 = session.client('ec2',region_name=region,config=AWS_CONFIG)
    inst = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
    tags = {t['Key']:t['Value'] for t in inst.get('Tags',[])}
    return {'id':instance_id,'name':tags.get('Name','Unnamed'),'state':inst['State']['Name'],
            'ip':inst.get('PublicIpAddress','—'),'private_ip':inst.get('PrivateIpAddress','—'),
            'type':inst['InstanceType'],'key_name':inst.get('KeyName','—'),
            'zone':inst['Placement']['AvailabilityZone'],'vpc':inst.get('VpcId','—')}


def control_instance(session, region, instance_id, action):
    ec2 = session.client('ec2',region_name=region,config=AWS_CONFIG)
    if action == 'start': ec2.start_instances(InstanceIds=[instance_id])
    elif action == 'stop': ec2.stop_instances(InstanceIds=[instance_id])
    elif action == 'reboot': ec2.reboot_instances(InstanceIds=[instance_id])
    elif action == 'terminate': ec2.terminate_instances(InstanceIds=[instance_id])
    else: raise ValueError('Unsupported action')


def cpu_metric(session,region,instance_id):
    client=session.client('cloudwatch',region_name=region,config=AWS_CONFIG)
    end=dt.datetime.now(dt.timezone.utc)
    start=end-dt.timedelta(minutes=30)
    resp=client.get_metric_statistics(Namespace='AWS/EC2',MetricName='CPUUtilization',
                                     Dimensions=[{'Name':'InstanceId','Value':instance_id}],
                                     StartTime=start,EndTime=end,Period=300,Statistics=['Average'])
    points=sorted(resp.get('Datapoints',[]),key=lambda p:p['Timestamp'])
    return round(points[-1]['Average'],1) if points else None


def monthly_cost(session):
    client=session.client('ce',region_name='us-east-1',config=AWS_CONFIG)
    today=dt.datetime.now(dt.timezone.utc).date()
    start=today.replace(day=1)
    end=today+dt.timedelta(days=1)
    report=client.get_cost_and_usage(TimePeriod={'Start':start.isoformat(),'End':end.isoformat()},
                                     Granularity='MONTHLY',Metrics=['UnblendedCost'])
    cost=report['ResultsByTime'][0]['Total']['UnblendedCost']
    return {'value':cost['Amount'],'currency':cost['Unit'],'estimated':report['ResultsByTime'][0].get('Estimated',True)}
