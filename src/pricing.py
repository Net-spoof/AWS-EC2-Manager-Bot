"""Public AWS EC2 On-Demand rates; no unverified or cross-Region fallback."""
import json
from decimal import Decimal, InvalidOperation
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

HOURS_PER_MONTH = Decimal('730')
PUBLIC_IPV4_USD_HOURLY = Decimal('0.005')
PRICE_CONFIG = Config(connect_timeout=5, read_timeout=16, retries={'max_attempts': 2, 'mode':'standard'})

# Official AWS billing/usage short codes:
# https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-region-billing-codes.html
# AmazonEC2 Price List products can omit "regionCode". Filter the actual
# usagetype instead; it is Region-qualified and supports exact TERM_MATCH.
REGION_BILLING_CODES = {
    'us-east-1': 'USE1', 'us-east-2': 'USE2', 'us-west-1': 'USW1',
    'us-west-2': 'USW2', 'ca-central-1': 'CAN1', 'ca-west-1': 'CAN2',
    'mx-central-1': 'MXC1', 'af-south-1': 'AFS1',
    'ap-east-1': 'APE1', 'ap-east-2': 'APE2',
    'ap-northeast-1': 'APN1', 'ap-northeast-2': 'APN2',
    'ap-northeast-3': 'APN3', 'ap-southeast-1': 'APS1',
    'ap-southeast-2': 'APS2', 'ap-southeast-3': 'APS4',
    'ap-southeast-4': 'APS6', 'ap-southeast-5': 'APS7',
    'ap-southeast-6': 'APS8', 'ap-southeast-7': 'APS9',
    'ap-south-1': 'APS3', 'ap-south-2': 'APS5',
    'eu-west-1': 'EU', 'eu-west-2': 'EUW2', 'eu-west-3': 'EUW3',
    'eu-central-1': 'EUC1', 'eu-central-2': 'EUC2',
    'eu-north-1': 'EUN1', 'eu-south-1': 'EUS1',
    'eu-south-2': 'EUS2', 'me-central-1': 'MEC1',
    'me-south-1': 'MES1', 'il-central-1': 'ILC1',
    'sa-east-1': 'SAE1',
}


def usage_codes(region, usage):
    """Candidate exact AWS usage types, with legacy unprefixed us-east-1."""
    prefix = REGION_BILLING_CODES.get(region)
    if prefix is None:
        raise ValueError('کد منطقه قیمت‌گذاری AWS هنوز شناخته نشده؛ قیمت حدس زده نمی‌شود.')
    if region == 'us-east-1':
        return [usage, f'{prefix}-{usage}']
    return [f'{prefix}-{usage}']


def _find_ondemand_rate(client, filters, unit, usage_suffix=None):
    """Search bounded pages of AWS Price List without selecting another Region.

    A lookup can have multiple SKUs or pages. Exact usagetype is required by
    quote_on_demand, and is checked again in the returned product metadata.
    """
    args = {
        'ServiceCode': 'AmazonEC2',
        'Filters': [{'Type': 'TERM_MATCH', 'Field': k, 'Value': v}
                    for k, v in filters.items()],
        'FormatVersion': 'aws_v1',
        'MaxResults': 25,
    }
    requested_usage = filters.get('usagetype')
    best = []
    for _ in range(8):
        response = client.get_products(**args)
        for raw in response.get('PriceList', []):
            product = json.loads(raw)
            attrs = product.get('product', {}).get('attributes', {})
            usage = attrs.get('usagetype', '')
            if requested_usage is not None and usage != requested_usage:
                continue
            if usage_suffix and not usage.endswith(usage_suffix):
                continue
            for term in product.get('terms', {}).get('OnDemand', {}).values():
                for dimension in term.get('priceDimensions', {}).values():
                    if dimension.get('unit') != unit:
                        continue
                    if str(dimension.get('beginRange', '0')) not in ('0', '0.0'):
                        continue
                    try:
                        amount = Decimal(dimension['pricePerUnit']['USD'])
                    except (KeyError, ValueError, InvalidOperation):
                        continue
                    if amount >= 0:
                        best.append(amount)
        next_token = response.get('NextToken')
        if not next_token:
            return min(best) if best else None
        args['NextToken'] = next_token
    # Fail closed if unprocessed pages remain rather than assert completeness.
    raise ValueError('تعداد نتایج تعرفه AWS زیاد است؛ استعلام کامل نشد.')


def _lookup_by_usage(client, region, usage, filters, unit):
    """Look up SKU by the official Region-specific AWS usagetype."""
    for code in usage_codes(region, usage):
        rate = _find_ondemand_rate(client, {**filters, 'usagetype': code}, unit, usage)
        if rate is not None:
            return rate
    return None


def quote_on_demand(session, region, instance_type, disk_gb, os_id="ubuntu", public_ipv4=True):
    """Quote region-specific EC2 + public IPv4 + gp3 capacity, 730-hour projection."""
    from .os_catalog import OS_CATALOG
    if os_id not in OS_CATALOG or OS_CATALOG[os_id]['pricing'] is None:
        raise ValueError('تعرفه این AMI باید جداگانه در AWS بررسی شود')
    client = session.client('pricing', region_name='us-east-1', config=PRICE_CONFIG)
    compute_filters = {
        'instanceType': instance_type,
        'operatingSystem': OS_CATALOG[os_id]['pricing'],
        'tenancy': 'Shared',
        'preInstalledSw': 'NA',
        'capacitystatus': 'Used',
    }
    compute = _lookup_by_usage(client, region, 'BoxUsage:' + instance_type,
                               compute_filters, 'Hrs')
    if compute is None:
        raise ValueError('تعرفه On-Demand این نوع سرور در ریجن انتخابی پیدا نشد.')
    storage = None
    if disk_gb is not None:
        try:
            storage = _lookup_by_usage(client, region, 'EBS:VolumeUsage.gp3',
                                       {}, 'GB-Mo')
        except (ClientError, BotoCoreError, ValueError):
            # No fabricated disk figure; the estimate explicitly excludes it.
            pass
    disk_month = storage * Decimal(disk_gb) if storage is not None else None
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


def pricing_error_text(exc):
    """Human-readable but secret-safe explanation of a failed AWS price lookup."""
    if isinstance(exc, ClientError):
        code = exc.response.get('Error', {}).get('Code', 'AWSAPIError')
        if code in ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
                    'UnrecognizedClientException', 'InvalidClientTokenId'):
            return ('❌ دسترسی AWS Pricing رد شد (' + code + '). '
                    'در IAM اکانت انتخاب‌شده مجوز pricing:GetProducts را بررسی کن.')
        if code in ('InvalidParameterException', 'ValidationException'):
            return ('❌ AWS فیلترهای استعلام قیمت را رد کرد (' + code + '). '
                    'نسخه ربات یا مشخصات منطقه را بررسی کن.')
        if code in ('ThrottlingException', 'TooManyRequestsException', 'RequestLimitExceeded'):
            return '⏳ محدودیت درخواست AWS Pricing؛ کمی بعد دوباره امتحان کن.'
        return f'❌ خطای AWS Pricing: {code}'
    if isinstance(exc, ValueError):
        return '❌ ' + str(exc)[:220]
    if isinstance(exc, (BotoCoreError, TimeoutError, ConnectionError, OSError)):
        return '❌ اتصال یا پاسخ AWS Pricing مشکل دارد؛ شبکه سرور ربات را بررسی کن.'
    return '❌ استعلام قیمت ناموفق بود؛ لاگ ربات را بررسی کن.'


def display_quote(quote, error=None):
    if not quote:
        return ('💵 قیمت: در حال حاضر قابل استعلام نیست.\n' +
                (error or 'مجوز pricing:GetProducts یا دسترسی به تعرفه AWS را بررسی کن.') +
                '\n⚠️ هزینه واقعی سرور در AWS Billing محاسبه می‌شود.')
    hourly = Decimal(quote['hourly'])
    monthly = Decimal(quote['monthly'])
    disk = quote.get('disk_monthly')
    return '\n'.join([
        '💵 قیمت تقریبی On-Demand (USD):',
        f"• خود EC2: ${Decimal(quote['compute_hourly']):.5f} در ساعت",
        f"• IPv4 عمومی: ${Decimal(quote['ipv4_hourly']):.3f} در ساعت",
        f'• دیسک gp3: ${Decimal(disk):.2f} در ماه' if disk is not None
        else '• دیسک EBS: قیمت نامشخص یا نوع غیر gp3 (در جمع منظور نشده)',
        f'• برآورد ساعتی: ${hourly:.5f}' + ('' if quote['complete'] else ' (بدون دیسک)'),
        f'• برآورد ماهانه (۷۳۰ ساعت): ${monthly:.2f}' + ('' if quote['complete'] else ' (بدون دیسک)'),
        '⚠️ ترافیک، مالیات، CPU Credit اضافی، تخفیف‌ها و سایر منابع در این مبلغ نیست.',
    ])


def os_from_instance(platform_details, platform):
    """Conservative pricing OS classification for existing EC2 instances."""
    detail = (platform_details or '').strip()
    if detail == 'Windows':
        return 'windows'
    if detail == 'Red Hat Enterprise Linux':
        return 'rhel'
    if detail == 'SUSE Linux':
        return 'suse'
    if detail in ('Linux/UNIX', 'Linux/UNIX (Amazon VPC)'):
        return 'ubuntu'
    if not detail and platform == 'windows':
        return 'windows'
    if not detail and platform == 'linux':
        return 'ubuntu'
    return None
