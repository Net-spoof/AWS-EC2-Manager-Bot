"""Safe sign-in hints from STS GetCallerIdentity.

GetCallerIdentity reports the API caller, *not* the AWS root email or
console password. The ARN for a role isn't an IAM-user username.
"""
import re

_ACCOUNT = re.compile(r'^\d{12}$')


def format_identity(account, identity):
    aws_id = identity.get('Account', '')
    if not isinstance(aws_id, str) or not _ACCOUNT.fullmatch(aws_id):
        raise ValueError('شناسه اکانت AWS نامعتبر است')
    arn = identity.get('Arn', '')
    if not isinstance(arn, str):
        arn = ''
    user = None
    role = None
    if arn.startswith(f'arn:aws:iam::{aws_id}:user/'):
        user = arn.rsplit('/', 1)[-1]
    elif ':assumed-role/' in arn:
        role = arn.split(':assumed-role/', 1)[-1].rsplit('/', 1)[0]
    connection = 'IAM Access Key' if account.get('kind') == 'keys' else 'IAM Role (AssumeRole)'
    lines = [
        '✅ اتصال AWS برقرار است',
        f"🔗 نام اکانت در ربات: {account.get('alias','—')}",
        f'🆔 AWS Account ID: {aws_id}',
        f'🔐 نوع اتصال: {connection}',
        f'🪪 هویت API (ARN): {arn or "نامشخص"}',
    ]
    if user:
        lines.extend([
            f'👤 IAM username: {user}',
            f'🌐 صفحه ورود IAM: https://{aws_id}.signin.aws.amazon.com/console/',
            '⚠️ این نام کاربری فقط برای ورود کنسول قابل استفاده است اگر قبلاً Console password و دسترسی لازم تنظیم شده باشند.',
        ])
    elif role:
        lines.extend([
            f'🎭 نام IAM Role: {role}',
            '⚠️ این یک Role است، نه نام کاربری IAM. با این ARN نمی‌توان مستقیم وارد کنسول شد.',
        ])
    else:
        lines.append('⚠️ این ARN نام کاربری کنسول IAM را مشخص نمی‌کند.')
    lines.append('🔒 ایمیل Root، رمز ورود و MFA از STS قابل بازیابی نیستند.')
    return '\n'.join(lines)
