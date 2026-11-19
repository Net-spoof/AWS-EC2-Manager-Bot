"""EC2 security group ingress management. Each mutation is bound to an instance SG.

Only IPv4 ingress is created here. Server-side lookups recheck group ownership and
SSH-protecting rules cannot be removed via the Telegram UI.
"""
import re

from .aws_api import AWS_CONFIG, validate_cidr


def _ec2(session, region):
    return session.client('ec2', region_name=region, config=AWS_CONFIG)


def attached_groups(session, region, instance_id):
    client = _ec2(session, region)
    rows = client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances']
    inst = rows[0]
    if inst['State']['Name'] == 'terminated':
        raise ValueError('Server is terminated')
    groups = inst.get('SecurityGroups', [])
    return [{'id': group['GroupId'], 'name': group.get('GroupName', '')} for group in groups]


def require_group(session, region, instance_id, group_id):
    if not any(item['id'] == group_id for item in attached_groups(session, region, instance_id)):
        raise ValueError('Security Group is no longer attached to this server')


def rules_for_instance(session, region, instance_id, group_id):
    require_group(session, region, instance_id, group_id)
    ec2 = _ec2(session, region)
    pages = ec2.get_paginator('describe_security_group_rules')
    result = []
    for page in pages.paginate(Filters=[{'Name': 'group-id', 'Values': [group_id]}]):
        for rule in page.get('SecurityGroupRules', []):
            if not rule.get('IsEgress', False):
                result.append(rule)
    return sorted(result, key=lambda x: (x.get('IpProtocol', ''), x.get('FromPort', -1), x.get('SecurityGroupRuleId', '')))


def parse_port(value):
    value = value.strip()
    parts = value.split('-')
    if not 1 <= len(parts) <= 2 or not all(p.isdigit() for p in parts):
        raise ValueError('Port must be 1-65535 or a range like 10000-10010')
    start = int(parts[0]); end = int(parts[-1])
    if not (1 <= start <= end <= 65535):
        raise ValueError('Invalid port or port range (1-65535)')
    return start, end


def is_ssh_protecting(rule):
    protocol = str(rule.get('IpProtocol', '')).lower()
    if protocol == '-1':
        return True
    return protocol in ('tcp', '6') and any(int(rule.get('FromPort', -1)) <= p <= int(rule.get('ToPort', -1)) for p in (22, 3389))


def fmt_rule(rule):
    proto = str(rule.get('IpProtocol', '?'))
    if proto == '-1':
        info = 'ALL traffic'
    elif proto == 'icmp':
        info = 'ICMP Echo (Ping)' if rule.get('FromPort') == 8 and rule.get('ToPort') == 0 else f"ICMP {rule.get('FromPort')}/{rule.get('ToPort')}"
    else:
        a, b = rule.get('FromPort'), rule.get('ToPort')
        info = f'{proto.upper()} {a}' if a == b else f'{proto.upper()} {a}-{b}'
    source = rule.get('CidrIpv4') or rule.get('CidrIpv6') or rule.get('PrefixListId') or rule.get('ReferencedGroupInfo', {}).get('GroupId') or 'other'
    return f'{info} · {source}'


def _rule_by_id(session, region, instance_id, group_id, rule_id):
    for rule in rules_for_instance(session, region, instance_id, group_id):
        if rule.get('SecurityGroupRuleId') == rule_id:
            return rule
    raise ValueError('Rule not found or removed')


def add_port(session, region, instance_id, group_id, protocol, port_start, port_end, cidr):
    require_group(session, region, instance_id, group_id)
    if protocol not in ('tcp', 'udp'):
        raise ValueError('Only TCP and UDP are allowed')
    if not (1 <= port_start <= port_end <= 65535):
        raise ValueError('Invalid port range')
    cidr = validate_cidr(cidr)
    if protocol == 'tcp' and cidr == '0.0.0.0/0' and any(port_start <= port <= port_end for port in (22,3389)):
        raise ValueError('Refusing to expose SSH or RDP to everyone; choose a specific /32 source')
    _ec2(session, region).authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{'IpProtocol': protocol, 'FromPort': port_start, 'ToPort': port_end,
                        'IpRanges': [{'CidrIp': cidr, 'Description': 'AWS-EC2-Manager-Bot'}]}])



# All bulk changes remain scoped to a Security Group currently attached to the selected
# EC2 instance. AWS Security Groups can be shared by several EC2 instances.
_BULK_DESCRIPTION = 'AWS-EC2-Manager-Bot bulk'
_MAX_BULK_RANGES = 20


def parse_port_list(value):
    """Parse at most 20 comma/space/newline-delimited ports or port ranges."""
    parts = [p for p in re.split(r'[,،\s]+', value.strip()) if p]
    if not parts or len(parts) > _MAX_BULK_RANGES:
        raise ValueError('Send 1-20 ports/ranges, e.g. 80,443,8080-8090')
    return list(dict.fromkeys(parse_port(p) for p in parts))


def _apply_bulk(session, region, instance_id, group_id, entries, cidr):
    """Add ingress permissions in one AWS API request, skipping exact existing rules."""
    require_group(session, region, instance_id, group_id)
    cidr = validate_cidr(cidr)
    entries = list(dict.fromkeys(entries))
    if not entries:
        raise ValueError('No ports selected')
    if len(entries) > 50:
        raise ValueError('Too many security group rules for one operation')
    for proto, start, end in entries:
        if proto not in ('tcp', 'udp') or not (1 <= start <= end <= 65535):
            raise ValueError('Invalid TCP/UDP port range')
        if cidr == '0.0.0.0/0' and (
            (proto == 'tcp' and (start <= 22 <= end or start <= 3389 <= end))
            or (proto == 'udp' and start <= 3389 <= end)
        ):
            raise ValueError('Refusing public SSH/RDP access; use a private /32 CIDR')

    current = rules_for_instance(session, region, instance_id, group_id)
    existing = {(str(r.get('IpProtocol', '')).lower(), r.get('FromPort'),
                 r.get('ToPort'), r.get('CidrIpv4')) for r in current}
    missing = [item for item in entries if (*item, cidr) not in existing]
    if not missing:
        return 0
    permissions = [
        {'IpProtocol': proto, 'FromPort': start, 'ToPort': end,
         'IpRanges': [{'CidrIp': cidr, 'Description': _BULK_DESCRIPTION}]}
        for proto, start, end in missing
    ]
    _ec2(session, region).authorize_security_group_ingress(
        GroupId=group_id, IpPermissions=permissions)
    return len(missing)


def add_port_batch(session, region, instance_id, group_id, protocols, ports, cidr):
    """Open multiple requested ports for TCP, UDP or both protocols."""
    protocols = list(dict.fromkeys(protocols))
    ports = list(ports)
    if not protocols or any(p not in ('tcp', 'udp') for p in protocols):
        raise ValueError('Select TCP and/or UDP')
    if not 1 <= len(ports) <= _MAX_BULK_RANGES:
        raise ValueError('Send 1-20 port ranges')
    return _apply_bulk(
        session, region, instance_id, group_id,
        [(proto, start, end) for proto in protocols for start, end in ports], cidr)


def open_all_ports(session, region, instance_id, group_id, cidr):
    """Open all TCP/UDP ports to a chosen CIDR. Public mode excludes SSH/RDP.

    For 0.0.0.0/0 we deliberately exclude TCP 22, TCP 3389 and UDP 3389.
    Existing access rules (including SSH/RDP) are never modified.
    """
    cidr = validate_cidr(cidr)
    if cidr == '0.0.0.0/0':
        entries = [
            ('tcp', 1, 21), ('tcp', 23, 3388), ('tcp', 3390, 65535),
            ('udp', 1, 3388), ('udp', 3390, 65535)
        ]
    else:
        entries = [('tcp', 1, 65535), ('udp', 1, 65535)]
    return _apply_bulk(session, region, instance_id, group_id, entries, cidr)


def managed_bulk_rules(rules):
    """Only rules stamped by these bulk controls can be bulk-revoked."""
    return [r for r in rules if r.get('Description') == _BULK_DESCRIPTION
            and r.get('SecurityGroupRuleId') and not r.get('IsEgress', False)]


def close_bulk_ports(session, region, instance_id, group_id):
    """Remove bot-created bulk rules, leaving all other SG rules unchanged."""
    rules = rules_for_instance(session, region, instance_id, group_id)
    ids = [r['SecurityGroupRuleId'] for r in managed_bulk_rules(rules)]
    if not ids:
        return 0
    # This can remove a bulk permission covering management ports. The UI requires
    # a separate confirmation warning of potential SSH/RDP loss of access.
    _ec2(session, region).revoke_security_group_ingress(
        GroupId=group_id, SecurityGroupRuleIds=ids)
    return len(ids)


def group_instance_count(session, region, instance_id, group_id):
    """Number of instances potentially affected by the shared Security Group."""
    require_group(session, region, instance_id, group_id)
    ec2 = _ec2(session, region)
    pages = ec2.get_paginator('describe_instances')
    ids = set()
    for page in pages.paginate(Filters=[{'Name': 'instance.group-id', 'Values': [group_id]}]):
        for reservation in page.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                if instance.get('State', {}).get('Name') != 'terminated':
                    ids.add(instance['InstanceId'])
    return len(ids)


def public_ping_enabled(rules):
    for r in rules:
        if r.get('CidrIpv4') != '0.0.0.0/0':
            continue
        proto = str(r.get('IpProtocol', '')).lower()
        if proto == '-1':
            return True
        if proto == 'icmp' and r.get('FromPort') in (8, -1) and r.get('ToPort') in (0, -1):
            return True
    return False


def enable_ping(session, region, instance_id, group_id):
    rules = rules_for_instance(session, region, instance_id, group_id)
    if public_ping_enabled(rules):
        return False
    _ec2(session, region).authorize_security_group_ingress(GroupId=group_id, IpPermissions=[
        {'IpProtocol': 'icmp', 'FromPort': 8, 'ToPort': 0,
         'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Ping (EC2 Manager Bot)'}]}])
    return True


def disable_ping(session, region, instance_id, group_id):
    rules = rules_for_instance(session, region, instance_id, group_id)
    rule_ids = [r['SecurityGroupRuleId'] for r in rules if r.get('IpProtocol') == 'icmp'
                and r.get('FromPort') == 8 and r.get('ToPort') == 0 and r.get('CidrIpv4') == '0.0.0.0/0']
    if public_ping_enabled(rules) and not rule_ids:
        raise ValueError('Ping is permitted by a broader SG rule. Modify that rule in AWS console.')
    if rule_ids:
        _ec2(session, region).revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=rule_ids)
    return len(rule_ids)


def remove_rule(session, region, instance_id, group_id, rule_id):
    rule = _rule_by_id(session, region, instance_id, group_id, rule_id)
    if is_ssh_protecting(rule):
        raise ValueError('SSH-protecting rules cannot be removed in the bot. Use AWS console.')
    _ec2(session, region).revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=[rule_id])
    return fmt_rule(rule)
