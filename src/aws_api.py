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
# Historical list retained only as a compatibility reference, not a launch allowlist.
REGIONS = ('eu-central-1','eu-central-2','eu-west-1','eu-west-2','eu-west-3','eu-north-1','eu-south-1','eu-south-2',
           'us-east-1','us-east-2','us-west-1','us-west-2','ca-central-1','ap-south-1','ap-south-2',
           'ap-southeast-1','ap-southeast-2','ap-northeast-1','ap-northeast-2','ap-northeast-3','me-central-1','me-south-1',
           'af-south-1','ap-east-1','ap-east-2','ap-southeast-3','ap-southeast-4','ap-southeast-5','ap-southeast-6',
           'ap-southeast-7','ca-west-1','il-central-1','mx-central-1','sa-east-1')
REGION_PATTERN = re.compile(r'^[a-z]{2}(?:-[a-z]+)+-[1-9][0-9]*$')


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


def region_catalog(session):
    """Use the account's real AWS Region opt-in status, not a fixed list."""
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


def cloud_init_password(password, root_login=False):
    """Generate Ubuntu user-data with salted password HASH only, never plaintext.

    root_login=True is an explicit opt-in. Both root and ubuntu get the generated
    password so the standard ubuntu account remains a recovery path.
    """
    salt = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    result = subprocess.run(['openssl', 'passwd', '-6', '-stdin', '-salt', f'rounds=120000${salt}'],
                            input=password + '\n', text=True, capture_output=True, check=True)
    hashed = result.stdout.strip()
    if not hashed.startswith('$6$rounds=120000$'):
        raise ValueError('Unable to generate SHA-512 crypt password hash')
    config = ('#cloud-config\n'
              'ssh_pwauth: true\n'
              + ('disable_root: false\n' if root_login else '')
              + 'chpasswd:\n  expire: false\n  users:\n'
              + f'    - name: ubuntu\n      password: "{hashed}"\n      type: hash\n')
    if root_login:
        config += (f'    - name: root\n      password: "{hashed}"\n      type: hash\n'
                   'write_files:\n'
                   '  - path: /etc/ssh/sshd_config.d/00-aws-ec2-manager-root.conf\n'
                   '    owner: root:root\n'
                   '    permissions: "0644"\n'
                   '    content: |\n'
                   '      PermitRootLogin yes\n'
                   '      PasswordAuthentication yes\n'
                   'runcmd:\n'
                   '  - [sh, -c, "sshd -t && systemctl reload ssh"]\n')
    return config


def make_password(length=26):
    alphabet = string.ascii_letters + string.digits + '!@#%-_+'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def create_instance(session, region, name, release, instance_type, disk_gb, ssh_cidr, access_mode, os_id="ubuntu", custom_ami=None):
    from .os_catalog import OS_CATALOG, resolve_image, is_windows, supports_password
    if not valid_region_id(region) or instance_type not in TYPES or os_id not in OS_CATALOG:
        raise ValueError('Invalid region, instance type or OS')
    if os_id != 'custom' and release not in OS_CATALOG[os_id]['versions']:
        raise ValueError('Invalid OS release')
    if access_mode in ('password', 'root_password') and not supports_password(os_id):
        raise ValueError('ورود با رمز اولیه فقط برای Ubuntu پشتیبانی می‌شود؛ کلید SSH انتخاب کن')
    if os_id == 'windows' and instance_type in ('t3.micro', 't3.small', 't3a.micro', 't3a.small'):
        raise ValueError('برای Windows Server حداقل ۴ گیگابایت RAM (t3.medium) انتخاب کن')
    if not (12 <= disk_gb <= 1024):
        raise ValueError('Disk should be between 12 and 1024 GiB')
    cidr = validate_cidr(ssh_cidr)
    if access_mode not in ('password','root_password','key'):
        raise ValueError('Invalid login mode')
    ec2 = session.client('ec2',region_name=region,config=AWS_CONFIG)
    vpc, subnet = ensure_default_vpc_subnet(ec2)
    image_info = resolve_image(session, region, os_id, release, custom_ami)
    ami = image_info['image_id']
    root_device = image_info['root_device']
    min_disk = image_info['minimum_disk']
    if disk_gb < min_disk:
        raise ValueError(f'این ایمیج حداقل {min_disk} GiB دیسک نیاز دارد')
    platform=image_info['platform']
    if platform=='windows' and access_mode!='key':
        raise ValueError('Windows Server به کلید خصوصی برای دریافت رمز Administrator نیاز دارد')
    password = make_password() if access_mode in ('password','root_password') else None
    security_group = None
    key_name = None
    key_material = None
    instance_id = None
    try:
        group_name = 'ec2-manager-' + uuid.uuid4().hex[:15]
        security_group = ec2.create_security_group(GroupName=group_name,
                       Description='Managed access for AWS EC2 Manager Bot',VpcId=vpc)['GroupId']
        port = 3389 if platform == 'windows' else 22
        ec2.authorize_security_group_ingress(GroupId=security_group, IpPermissions=[{
            'IpProtocol':'tcp','FromPort':port,'ToPort':port,
            'IpRanges':[{'CidrIp':cidr,'Description':'RDP access' if port==3389 else 'SSH access'}]}])
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
            params['UserData'] = cloud_init_password(password, root_login=access_mode == 'root_password')
        instance_id = ec2.run_instances(**params)['Instances'][0]['InstanceId']
        return {'id':instance_id,'password':password,'pem':key_material,'key_name':key_name,
                'sg_id':security_group, 'platform':platform, 'user':'root' if access_mode == 'root_password' else image_info['user'],
                'ami':ami, 'os_id':os_id}
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
            'zone':inst['Placement']['AvailabilityZone'],'vpc':inst.get('VpcId','—'),
            'platform':'windows' if inst.get('Platform')=='windows' or 'Windows' in inst.get('PlatformDetails','') else 'linux',
            'platform_details':inst.get('PlatformDetails',''),
            'spot':inst.get('InstanceLifecycle')=='spot',
            'volume_ids':[item['Ebs']['VolumeId'] for item in inst.get('BlockDeviceMappings',[])
                          if item.get('Ebs',{}).get('VolumeId')]}


def instance_volume_info(session, region, volume_ids):
    """Return the real EBS size when all attached volumes are gp3.

    Unknown or mixed types are deliberately excluded from the priced total.
    """
    if not volume_ids:
        return {'disk_gb':None,'label':'اطلاعات EBS موجود نیست'}
    ec2=session.client('ec2',region_name=region,config=AWS_CONFIG)
    volumes=ec2.describe_volumes(VolumeIds=volume_ids).get('Volumes',[])
    if len(volumes)!=len(volume_ids):
        return {'disk_gb':None,'label':'اطلاعات بعضی دیسک‌ها ناقص است'}
    desc=', '.join(f"{vol['Size']} GiB {vol['VolumeType']}" for vol in volumes)
    gp3=all(vol.get('VolumeType')=='gp3' for vol in volumes)
    total=sum(vol['Size'] for vol in volumes) if gp3 else None
    return {'disk_gb':total,'label':desc, 'only_gp3':gp3}


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
    if not report.get('ResultsByTime'):
        raise ValueError('AWS Cost Explorer returned no billing periods')
    cost=report['ResultsByTime'][0]['Total']['UnblendedCost']
    return {'value':cost['Amount'],'currency':cost['Unit'],'estimated':report['ResultsByTime'][0].get('Estimated',True)}
