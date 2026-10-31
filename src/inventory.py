"""Collect a single AWS account's EC2 instances across its enabled Regions.

Create boto3 clients sequentially (Sessions are not documented thread-safe);
then perform API calls using the already-created clients in a bounded pool.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from .aws_api import AWS_CONFIG, region_catalog

PAGE_SIZE = 10


def _region_instances(ec2, region):
    rows = []
    for page in ec2.get_paginator('describe_instances').paginate(PaginationConfig={'PageSize': 100}):
        for reservation in page.get('Reservations', []):
            for inst in reservation.get('Instances', []):
                state = inst.get('State', {}).get('Name', 'unknown')
                if state == 'terminated':
                    continue
                tags = {t['Key']: t['Value'] for t in inst.get('Tags', [])}
                rows.append({
                    'id': inst['InstanceId'],
                    'name': tags.get('Name', 'Unnamed')[:60],
                    'state': state,
                    'ip': inst.get('PublicIpAddress', '—'),
                    'type': inst.get('InstanceType', '—'),
                    'region': region,
                    'launched': str(inst.get('LaunchTime', '')),
                })
    return rows


def list_account_instances(session):
    """Return (instances, failed_regions, scanned_regions).

    Errors are reported separately; a partial scan is never presented as
    a complete inventory. Avoid displaying AWS exception details in Telegram.
    """
    regions, _ = region_catalog(session)
    clients, failed = [], []
    for region in regions:
        try:
            clients.append((region, session.client('ec2', region_name=region, config=AWS_CONFIG)))
        except Exception:
            failed.append(region)
    rows = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(_region_instances, client, region): region for region, client in clients}
        for future in as_completed(futures):
            region = futures[future]
            try:
                rows.extend(future.result())
            except Exception:
                failed.append(region)
    rows.sort(key=lambda x: (x['launched'], x['id']), reverse=True)
    return rows, sorted(failed), len(regions)


def server_page(instances, page, page_size=PAGE_SIZE):
    """Validate paging; empty inventory has exactly one empty page."""
    if not isinstance(page, int) or page < 0 or page_size < 1:
        raise ValueError('Invalid inventory page')
    total_pages = max(1, (len(instances) + page_size - 1) // page_size)
    if page >= total_pages:
        raise ValueError('Inventory page no longer exists; refresh the list.')
    return instances[page * page_size:(page + 1) * page_size], total_pages
