"""Safe, actionable AWS EC2 launch permission diagnostics.

Never show AWS encoded authorization messages, credentials, or raw exceptions
in a bot chat. Expose only action, region and independently identified deny type.
"""
import re
from botocore.exceptions import ClientError


class EC2LaunchPermissionError(Exception):
    def __init__(self, operation, region, code, deny_type=None):
        super().__init__(code)
        self.operation = operation
        self.region = region
        self.code = code
        self.deny_type = deny_type


_AWS_ACTIONS = {
    'DescribeVpcs': 'ec2:DescribeVpcs',
    'DescribeSubnets': 'ec2:DescribeSubnets',
    'DescribeImages': 'ec2:DescribeImages',
    'GetParameter': 'ssm:GetParameter',
    'CreateSecurityGroup': 'ec2:CreateSecurityGroup',
    'AuthorizeSecurityGroupIngress': 'ec2:AuthorizeSecurityGroupIngress',
    'CreateKeyPair': 'ec2:CreateKeyPair',
    'RunInstances': 'ec2:RunInstances',
}
_DENIED_CODES = frozenset(('UnauthorizedOperation', 'AccessDenied',
                           'AccessDeniedException', 'Client.UnauthorizedOperation'))


def transform_launch_denial(exc, fallback_step, region):
    """Return a contextual exception for AWS auth denies; do not infer cause."""
    if not isinstance(exc, ClientError):
        return None
    err = exc.response.get('Error', {})
    code = err.get('Code', '')
    if code not in _DENIED_CODES:
        return None
    operation = _AWS_ACTIONS.get(getattr(exc, 'operation_name', ''), fallback_step)
    message = err.get('Message', '').lower()
    deny_type = None
    if ('service control policy' in message or 'service control policies' in message):
        deny_type = 'SCP'
    elif 'permissions boundary' in message:
        deny_type = 'Permissions Boundary'
    elif 'no identity-based policy allows' in message:
        deny_type = 'IAM'
    return EC2LaunchPermissionError(operation, region, code, deny_type)


def display_launch_denial(exc):
    lines = [
        'AWS اجازه اجرای یکی از عملیات ساخت سرور را نداده است.',
        f'🛑 عملیات ردشده: {exc.operation}',
        f'🌍 ریجن: {exc.region}',
        f'کد AWS: {exc.code}',
    ]
    if exc.deny_type == 'SCP':
        lines.append('🛡 علت اعلام‌شده AWS: محدودیت سازمانی SCP؛ تغییر مجوز IAM به‌تنهایی کافی نیست.')
    elif exc.deny_type == 'Permissions Boundary':
        lines.append('🛡 علت اعلام‌شده AWS: Permissions Boundary.')
    elif exc.deny_type == 'IAM':
        lines.append('🛡 علت اعلام‌شده AWS: مجوز مناسب در IAM یافت نشد.')
    else:
        lines.append('🛡 علت دقیق از کد خطا به‌تنهایی مشخص نیست (IAM، SCP یا شرط‌های دسترسی ممکن‌اند).')
    lines.extend([
        'اگر AWS Projects / Free Plan داری، ریجن را با ریجن اصلی پروژه در AWS Settings مقایسه کن.',
        'اگر عملیات ec2:RunInstances است، از داخل AWS Console یا پیام رمزگذاری‌شده Authorization Failure برای تشخیص سیاست مسدودکننده استفاده کن.',
        '⚠️ AdministratorAccess محدودیت SCP را برطرف نمی‌کند. برای این خطا مجوزها را کورکورانه گسترش نده.',
    ])
    return '\n'.join(lines)


class EC2LaunchParameterError(Exception):
    def __init__(self, operation, region, code, reason):
        super().__init__(code)
        self.operation, self.region = operation, region
        self.code, self.reason = code, reason


def transform_launch_parameter_error(exc, stage, region):
    """Preserve operation and safe service validation explanation, not credentials."""
    if not isinstance(exc, ClientError):
        return None
    e=exc.response.get('Error',{})
    code=e.get('Code','')
    if code not in ('InvalidParameterCombination','InvalidParameterValue',
                    'InvalidBlockDeviceMapping','InvalidParameter'):
        return None
    msg=e.get('Message','')
    if not isinstance(msg,str):
        msg=''
    msg=' '.join(msg.split())
    if (len(msg)>500 or re.search(
        r'(?i)(secret|password|credential|access.?key|session.?token|'
        r'encoded|authorization|user.?data|cloud.?init|bearer|arn:aws:|https?://|'
        r'AKIA[A-Z0-9]{10}|ASIA[A-Z0-9]{10}|'
        r'[A-Za-z0-9+/=_-]{60,})',msg)
        or re.search(r'@|\b[0-9]{12}\b',msg)):
        msg=''
    return EC2LaunchParameterError(
        getattr(exc,'operation_name',None) or stage, region, code, msg[:320])


def display_launch_parameter_error(exc):
    return ('❌ AWS پارامترهای ساخت سرور را رد کرد.\n'
            f'🛑 مرحله: {exc.operation}\n'
            f'🌍 ریجن: {exc.region}\n'
            f'کد AWS: {exc.code}\n'
            + (f'📋 دلیل AWS: {exc.reason}\n' if exc.reason else
               '📋 شرح AWS قابل نمایش امن نبود.\n')
            + 'ℹ️ این خطا لزوماً مشکل مجوز IAM نیست. نوع سرور، AMI، دیسک و شبکه را بررسی کن.')
