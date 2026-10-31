"""Allowlisted OS choices and AWS AMI discovery for x86_64 EBS-based EC2."""
import re

# Registry is *not* an exhaustive catalog of AWS Marketplace products.
# Advanced users can choose any accessible compatible AMI by its ID.
OS_CATALOG = {
    'ubuntu': {'label':'🐧 Ubuntu Server', 'versions': {'22.04':'22.04 LTS', '24.04':'24.04 LTS', '26.04':'26.04 LTS'}, 'user':'ubuntu', 'pricing':'Linux', 'password':True},
    'debian': {'label':'🌀 Debian GNU/Linux', 'versions': {'12':'12 (Bookworm)', '13':'13 (Trixie)'}, 'user':'admin', 'pricing':'Linux', 'password':False},
    'amazon': {'label':'☁️ Amazon Linux', 'versions': {'2023':'Amazon Linux 2023', '2':'Amazon Linux 2'}, 'user':'ec2-user', 'pricing':'Linux', 'password':False},
    'windows': {'label':'🪟 Windows Server', 'versions': {'2019':'Windows Server 2019', '2022':'Windows Server 2022', '2025':'Windows Server 2025'}, 'user':'Administrator', 'pricing':'Windows', 'password':False, 'rdp':True},
    'rhel': {'label':'🎩 Red Hat Enterprise Linux', 'versions': {'8':'RHEL 8', '9':'RHEL 9', '10':'RHEL 10'}, 'user':'ec2-user', 'pricing':'RHEL', 'password':False},
    'suse': {'label':'🦎 SUSE Linux Enterprise', 'versions': {'15':'SLES 15'}, 'user':'ec2-user', 'pricing':'SUSE', 'password':False},
    'rocky': {'label':'⛰️ Rocky Linux', 'versions': {'8':'Rocky Linux 8', '9':'Rocky Linux 9'}, 'user':'rocky', 'pricing':None, 'password':False},
    'custom': {'label':'🛠 سایر سیستم‌عامل‌ها (AMI دلخواه)', 'versions': {}, 'user':None, 'pricing':None, 'password':False},
}
SSM_PATHS = {
    ('amazon','2023'): '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64',
    ('amazon','2'): '/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2',
    ('windows','2019'): '/aws/service/ami-windows-latest/Windows_Server-2019-English-Full-Base',
    ('windows','2022'): '/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base',
    ('windows','2025'): '/aws/service/ami-windows-latest/Windows_Server-2025-English-Full-Base',
}
# Publishers documented by their respective projects. Search only EBS x86_64 AMIs.
PUBLISHED_IMAGES = {
    'debian': ('136693071363', 'debian-{version}-amd64-*'),
    'rhel': ('309956199498', 'RHEL-{version}*_HVM-*-x86_64-*-Hourly*'),
    'suse': ('013907871322', 'suse-sles-{version}-sp*-v*-hvm-ssd-x86_64*'),
    'rocky': ('792107900819', 'Rocky-{version}-EC2-Base-*-x86_64*'),
}
AMI_ID = re.compile(r'^ami-[0-9a-f]{8}(?:[0-9a-f]{9})?$')


def os_label(os_id, version):
    if os_id == 'custom':
        return '🛠 AMI دلخواه'
    family = OS_CATALOG[os_id]
    return f"{family['label']} — {family['versions'][version]}"


def os_login(os_id):
    return OS_CATALOG[os_id]['user']


def supports_password(os_id):
    return OS_CATALOG[os_id]['password']


def is_windows(os_id):
    return bool(OS_CATALOG[os_id].get('rdp'))


def resolve_image(session, region, os_id, version, ami_id=None):
    """Resolve a publisher-verified AMI with Architecture x86_64 and EBS root.

    Custom images require an explicit exact AMI ID; Windows images are always
    detected from EC2 metadata so a Windows AMI cannot be mislaunched as Linux.
    """
    if os_id not in OS_CATALOG:
        raise ValueError('سیستم‌عامل انتخاب‌شده معتبر نیست')
    if os_id != 'custom' and version not in OS_CATALOG[os_id]['versions']:
        raise ValueError('نسخه سیستم‌عامل معتبر نیست')
    ec2 = session.client('ec2', region_name=region)
    expected_owner = None
    if os_id == 'custom':
        if not isinstance(ami_id,str) or not AMI_ID.fullmatch(ami_id):
            raise ValueError('شناسه AMI معتبر نیست (مثال: ami-0123456789abcdef0)')
    elif os_id == 'ubuntu':
        # Imported lazily to avoid a circular module dependency.
        from .aws_api import resolve_ubuntu_ami
        ami_id = resolve_ubuntu_ami(session, region, version)
        expected_owner = '099720109477'
    elif (os_id, version) in SSM_PATHS:
        ssm = session.client('ssm', region_name=region)
        ami_id = ssm.get_parameter(Name=SSM_PATHS[(os_id, version)])['Parameter']['Value']
    else:
        owner, pattern = PUBLISHED_IMAGES[os_id]
        response = ec2.describe_images(Owners=[owner], Filters=[
            {'Name':'name', 'Values':[pattern.format(version=version)]},
            {'Name':'architecture', 'Values':['x86_64']},
            {'Name':'root-device-type', 'Values':['ebs']},
            {'Name':'state', 'Values':['available']},
        ])
        images = [image for image in response.get('Images', [])
                  if image.get('OwnerId',owner) == owner
                  and image.get('Name','').lower().find('arm64') == -1
                  and image.get('State','available') == 'available'
                  and image.get('DeprecationTime') is None]
        if os_id == 'debian':
            images = [image for image in images if not image.get('Name','').startswith(f'debian-{version}-backports')]
        if os_id == 'rhel':
            images = [image for image in images if 'Hourly' in image.get('Name','')]
        if not images:
            raise ValueError('ایمیج رسمی این نسخه در ریجن انتخابی پیدا نشد. نسخه دیگری را انتخاب کن یا AMI دلخواه وارد کن.')
        ami_id = max(images, key=lambda x: x.get('CreationDate',''))['ImageId']
        expected_owner = owner
    result = ec2.describe_images(ImageIds=[ami_id])['Images']
    if not result:
        raise ValueError('AMI قابل دسترسی نیست')
    image = result[0]
    if expected_owner and image.get('OwnerId') and image['OwnerId'] != expected_owner:
        raise ValueError('ناشر AMI با ناشر رسمی سیستم‌عامل مطابقت ندارد')
    if image.get('Architecture','x86_64') != 'x86_64' or image.get('RootDeviceType','ebs') != 'ebs':
        raise ValueError('فقط AMI با معماری x86_64 و ریشه EBS پشتیبانی می‌شود')
    if image.get('State','available') != 'available':
        raise ValueError('AMI در وضعیت available نیست')
    is_win = image.get('Platform') == 'windows' or 'Windows' in image.get('PlatformDetails','')
    if os_id == 'custom':
        platform='windows' if is_win else 'linux'
    else:
        platform='windows' if is_windows(os_id) else 'linux'
        if is_win != is_windows(os_id):
            raise ValueError('نوع سیستم‌عامل AMI با گزینه انتخابی مطابقت ندارد')
    root = image.get('RootDeviceName') or '/dev/sda1'
    minimum = 8
    for block in image.get('BlockDeviceMappings', []):
        if block.get('DeviceName') == root:
            minimum = int(block.get('Ebs',{}).get('VolumeSize',minimum))
            break
    return {'image_id':ami_id, 'root_device':root, 'minimum_disk':max(12,minimum),
            'platform':platform, 'user':OS_CATALOG[os_id]['user'],
            'name':image.get('Name',''), 'os_id':os_id}
