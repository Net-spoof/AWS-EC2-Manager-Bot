"""Side-effect-free, per-account probes for EC2 launch eligibility by Region.

A positive AWS DryRun response is evidence of permission for the *test*
configuration, not a guarantee of future EC2 capacity, quotas or other AMIs.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.config import Config
from botocore.exceptions import ClientError

from .aws_api import region_catalog, ensure_default_vpc_subnet

PROBE_CONFIG = Config(connect_timeout=4, read_timeout=10,
                      retries={'max_attempts': 1, 'mode': 'standard'})
PROBE_INSTANCE_TYPE = 't3.small'
PROBE_SSM_PATH = ('/aws/service/canonical/ubuntu/server/noble/stable/'
                  'current/amd64/hvm/ebs-gp3/ami-id')
DENIED_CODES = frozenset((
    'UnauthorizedOperation', 'Client.UnauthorizedOperation',
    'AccessDenied', 'AccessDeniedException',
))


def _dryrun(call, **kwargs):
    """Only documented DryRunOperation counts as a positive authorization."""
    try:
        call(DryRun=True, **kwargs)
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code', '')
        if code == 'DryRunOperation':
            return 'allowed'
        if code in DENIED_CODES:
            return 'blocked'
        return 'unknown'
    except Exception:
        return 'unknown'
    # A successful mutation response with DryRun requested is unexpected.
    return 'unknown'


def _probe_region(ec2, ssm):
    try:
        vpc, subnet = ensure_default_vpc_subnet(ec2)
    except ClientError as exc:
        return ('blocked' if exc.response.get('Error', {}).get('Code') in DENIED_CODES
                else 'unknown')
    except ValueError:
        # This bot only creates instances in a default VPC and default subnet.
        return 'blocked'
    except Exception:
        return 'unknown'

    group_status = _dryrun(
        ec2.create_security_group,
        GroupName='ec2-manager-preflight-check',
        Description='DryRun permission test; never create a group',
        VpcId=vpc,
    )
    if group_status != 'allowed':
        return group_status

    try:
        ami = ssm.get_parameter(Name=PROBE_SSM_PATH)['Parameter']['Value']
        root_device = ec2.describe_images(ImageIds=[ami])['Images'][0]['RootDeviceName']
    except ClientError as exc:
        return ('blocked' if exc.response.get('Error', {}).get('Code') in DENIED_CODES
                else 'unknown')
    except Exception:
        return 'unknown'

    return _dryrun(
        ec2.run_instances,
        ImageId=ami, InstanceType=PROBE_INSTANCE_TYPE,
        MinCount=1, MaxCount=1,
        NetworkInterfaces=[{
            'DeviceIndex': 0, 'SubnetId': subnet,
            'AssociatePublicIpAddress': True, 'DeleteOnTermination': True,
        }],
        BlockDeviceMappings=[{
            'DeviceName': root_device,
            'Ebs': {
                'VolumeSize': 20, 'VolumeType': 'gp3',
                'Encrypted': True, 'DeleteOnTermination': True,
            },
        }],
        MetadataOptions={'HttpTokens': 'required', 'HttpEndpoint': 'enabled'},
        TagSpecifications=[{
            'ResourceType': 'instance',
            'Tags': [{'Key': 'ManagedBy', 'Value': 'AWS-EC2-Manager-Bot'}],
        }],
    )


def find_launchable_regions(session, max_workers=6):
    """Return (verified, blocked, unknown, opt_in_disabled) for one AWS session.

    Create session clients sequentially, then query distinct clients in a
    bounded pool. No writable AWS API is called without DryRun=True.
    """
    enabled, inactive = region_catalog(session)
    clients, unknown = [], []
    for region in enabled:
        try:
            ec2 = session.client('ec2', region_name=region, config=PROBE_CONFIG)
            ssm = session.client('ssm', region_name=region, config=PROBE_CONFIG)
            clients.append((region, ec2, ssm))
        except Exception:
            unknown.append(region)
    verified, blocked = [], []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_probe_region, ec2, ssm): region
            for region, ec2, ssm in clients
        }
        for future in as_completed(futures):
            region = futures[future]
            try:
                result = future.result()
            except Exception:
                result = 'unknown'
            if result == 'allowed':
                verified.append(region)
            elif result == 'blocked':
                blocked.append(region)
            else:
                unknown.append(region)
    return sorted(verified), sorted(blocked), sorted(unknown), sorted(inactive)
