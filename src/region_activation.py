"""AWS Account Management Region opt-in operations.

Only the selected AWS account is affected. Operations intentionally omit AccountId
because IAM credentials already represent the selected account. No disable operation.
"""
from .aws_api import AWS_CONFIG, valid_region_id

REGION_STATUSES = frozenset({
    'ENABLED', 'ENABLED_BY_DEFAULT', 'ENABLING', 'DISABLING', 'DISABLED'
})


def _account_client(session):
    return session.client('account', region_name='us-east-1', config=AWS_CONFIG)


def get_opt_status(session, region):
    if not valid_region_id(region):
        raise ValueError('Invalid AWS Region code')
    response = _account_client(session).get_region_opt_status(RegionName=region)
    status = response.get('RegionOptStatus')
    if status not in REGION_STATUSES:
        raise ValueError('Unknown AWS Region opt-in status')
    return status


def enable_opt_region(session, region):
    """Idempotent: only issue EnableRegion for a confirmed DISABLED Region."""
    if not valid_region_id(region):
        raise ValueError('Invalid AWS Region code')
    client = _account_client(session)
    status = client.get_region_opt_status(RegionName=region).get('RegionOptStatus')
    if status not in REGION_STATUSES:
        raise ValueError('Unknown AWS Region opt-in status')
    if status == 'DISABLED':
        client.enable_region(RegionName=region)
        return 'ENABLING'
    # An in-progress opt-in cannot be cancelled or enabled a second time.
    return status



REGION_ACCESS_DENIED = (
    '❌ AWS دسترسی بررسی یا فعال‌سازی این لوکیشن را رد کرد (AccessDenied).\\n'
    'اگر اکانت را از AWS Builder ID / Projects ساخته‌ای، '
    'در تجربه جدید AWS یک محدودیت سازمانی (SCP) حتی با وجود مجوز IAM، '
    'account:GetRegionOptStatus و account:EnableRegion را مسدود می‌کند.\\n'
    'برای استفاده از ریجن‌های دیگر باید Paid Plan و سپس Advanced Features '
    'را در AWS Settings فعال کنی؛ این کار می‌تواند امکان دریافت '
    'کردیت‌های اضافه فعالیت‌ها را از بین ببرد.\\n'
    'اگر اکانت Advanced است، IAM Policy، SCP و Permissions Boundary '
    'هویت API متصل‌شده را بررسی کن. اضافه‌کردن AdministratorAccess '
    'محدودیت SCP را دور نمی‌زند.'
)
