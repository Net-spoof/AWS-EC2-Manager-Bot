"""Public On-Demand AWS price quotes (never infer an unverified EC2 rate)."""
import json
from decimal import Decimal, InvalidOperation
from botocore.config import Config

HOURS_PER_MONTH = Decimal('730')
PUBLIC_IPV4_USD_HOURLY = Decimal('0.005')  # AWS's published standard in-use IPv4 price.
PRICE_CONFIG = Config(connect_timeout=5, read_timeout=12, retries={'max_attempts': 1})


def _find_ondemand_rate(client, filters, unit, usage_suffix=None):
    response = client.get_products(
        ServiceCode='AmazonEC2',
        Filters=[{'Type': 'TERM_MATCH', 'Field': key, 'Value': value} for key, value in filters.items()],
        FormatVersion='aws_v1', MaxResults=25)
    rates = []
    for text in response.get('PriceList', []):
        product = json.loads(text)
        attributes = product.get('product', {}).get('attributes', {})
        usage = attributes.get('usagetype', '')
        if usage_suffix and not usage.endswith(usage_suffix):
            continue
        for term in product.get('terms', {}).get('OnDemand', {}).values():
            for dimension in term.get('priceDimensions', {}).values():
                if dimension.get('unit') != unit or str(dimension.get('beginRange','0')) not in ('0','0.0'):
                    continue
                try:
                    usd = Decimal(dimension['pricePerUnit']['USD'])
                except (KeyError, ValueError, InvalidOperation):
                    continue
                if usd >= 0:
                    rates.append(usd)
    if not rates:
        return None
    return min(rates)


def quote_on_demand(session, region, instance_type, disk_gb, os_id="ubuntu", public_ipv4=True):
    """Quote EC2 instance, gp3 root disk and 1 public IPv4 separately.

    If official EC2 price is unavailable, return explicit unknown rather than
    fabricated numbers. gp3 storage is only included in totals if priced.
    This is NOT a bill: excludes traffic, credits, tax, discounts, snapshots.
    """
    from .os_catalog import OS_CATALOG
    if os_id not in OS_CATALOG or OS_CATALOG[os_id]['pricing'] is None:
        raise ValueError('تعرفه این AMI باید جداگانه در AWS بررسی شود')
    client = session.client('pricing', region_name='us-east-1', config=PRICE_CONFIG)
    os_price = OS_CATALOG[os_id]['pricing']
    compute_filters = {
        'regionCode': region,
        'instanceType': instance_type,
        'operatingSystem': os_price,
        'tenancy': 'Shared',
        'preInstalledSw': 'NA',
        'capacitystatus': 'Used',
    }
    compute = _find_ondemand_rate(client, compute_filters, 'Hrs', 'BoxUsage:' + instance_type)
    if compute is None:
        raise ValueError('On-Demand Linux EC2 price not found for this Region/type')
    # Official gp3 catalog item, billed per GB-month. Not a hardcoded global rate.
    storage = None
    try:
        storage = _find_ondemand_rate(client, {
            'regionCode': region, 'volumeApiName': 'gp3',
        }, 'GB-Mo', 'EBS:VolumeUsage.gp3')
    except Exception:
        pass  # A partial quote is clearly labeled below.
    disk_month = storage * Decimal(disk_gb) if storage is not None and disk_gb is not None else None
    ipv4_hourly = PUBLIC_IPV4_USD_HOURLY if public_ipv4 else Decimal('0')
    monthly = (compute + ipv4_hourly) * HOURS_PER_MONTH
    if disk_month is not None:
        monthly += disk_month
    return {
        'compute_hourly': str(compute),
        'ipv4_hourly': str(ipv4_hourly),
        'disk_monthly': str(disk_month) if disk_month is not None else None,
        'hourly': str(monthly / HOURS_PER_MONTH),
        'monthly': str(monthly),
        'complete': disk_month is not None,
        'currency': 'USD',
    }


def display_quote(quote):
    """Localize an estimate consistently before and after a launch."""
    if not quote:
        return ('💵 قیمت: در حال حاضر قابل استعلام نیست (نیاز به pricing:GetProducts).\n'
                'برای بررسی تعرفه از AWS Pricing Calculator استفاده کن.\n'
                '⚠️ ساخت سرور همچنان مشمول هزینه واقعی است.')
    hourly = Decimal(quote['hourly'])
    monthly = Decimal(quote['monthly'])
    disk = quote.get('disk_monthly')
    lines = [
        '💵 قیمت تقریبی On-Demand (USD):',
        f"• خود EC2: ${Decimal(quote['compute_hourly']):.5f} در ساعت",
        f"• IPv4 عمومی: ${Decimal(quote['ipv4_hourly']):.3f} در ساعت",
        f'• دیسک gp3: ${Decimal(disk):.2f} در ماه' if disk is not None else '• دیسک EBS: قیمت نامشخص یا نوع غیر gp3 (در جمع منظور نشده)',
        f'• برآورد ساعتی: ${hourly:.5f}' + ('' if quote['complete'] else ' (بدون دیسک)'),
        f'• برآورد ماهانه (۷۳۰ ساعت): ${monthly:.2f}' + ('' if quote['complete'] else ' (بدون دیسک)'),
        '⚠️ ترافیک، مالیات، CPU Credit اضافی، تخفیف‌ها و سایر منابع در این مبلغ نیست.',
    ]
    return '\n'.join(lines)


def os_from_instance(platform_details, platform):
    """Conservatively classify the actual EC2 billing platform.

    Licensed or Marketplace AMIs with ambiguous metadata get no quote.
    """
    detail=(platform_details or '').strip()
    if detail=='Windows':
        return 'windows'
    if detail=='Red Hat Enterprise Linux':
        return 'rhel'
    if detail=='SUSE Linux':
        return 'suse'
    if detail in ('Linux/UNIX','Linux/UNIX (Amazon VPC)'):
        return 'ubuntu'  # unlicensed Linux On-Demand rate
    if not detail and platform=='windows':
        return 'windows'
    if not detail and platform=='linux':
        return 'ubuntu'
    return None
