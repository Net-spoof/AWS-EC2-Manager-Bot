"""Clear, safe presentation of AWS Cost Explorer billing responses.

DataUnavailableException means AWS has no report to return for this request;
it does not mean the total charge is zero. Never replace missing bill data
with estimated EC2 pricing.
"""
from decimal import Decimal
from botocore.exceptions import ClientError


def format_billing_success(account_alias, info):
    amount = Decimal(str(info['value']))
    currency = info['currency']
    estimated = bool(info.get('estimated', True))
    return (
        f'💰 هزینه گزارش‌شده ماه جاری برای {account_alias}: {amount:.2f} {currency}\n'
        + ('⏳ این مبلغ هنوز نهایی نیست.\n' if estimated else '')
        + 'ℹ️ اطلاعات AWS Cost Explorer حداقل روزانه به‌روزرسانی می‌شود. '
          'اعتبارهای رایگان، تخفیف‌ها و پرداخت نهایی ممکن است جداگانه محاسبه شوند.'
    )


def format_billing_error(exc):
    if isinstance(exc, ClientError):
        code = exc.response.get('Error', {}).get('Code', '')
        if code == 'DataUnavailableException':
            return (
                '📊 صورتحساب AWS هنوز قابل استعلام نیست.\n\n'
                'AWS Cost Explorer برای این درخواست داده‌ای ارائه نکرده است. '
                'این وضعیت در اکانت تازه‌ساخته‌شده یا پیش از آماده‌شدن '
                'گزارش‌های Cost Explorer رخ می‌دهد.\n'
                '• اگر Cost Explorer را تازه فعال کرده‌ای، آماده‌شدن اطلاعات '
                'ماه جاری معمولاً حدود ۲۴ ساعت طول می‌کشد.\n'
                '• در AWS Console بخش Billing and Cost Management → Cost Explorer را بررسی کن. '
                'برای اکانت‌های AWS Projects، قسمت Billing در AWS Settings هم مفید است.\n\n'
                '⚠️ مبلغ نامشخص است، نه لزوماً صفر دلار. '
                'هیچ مجوز IAM جدیدی صرفاً به خاطر این خطا لازم نیست.'
            )
        if code in ('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation'):
            return (
                f'❌ AWS Cost Explorer دسترسی را رد کرد ({code}).\n'
                'مجوز ce:GetCostAndUsage، محدودیت سازمانی SCP و دسترسی '
                'به داده‌های Billing در اکانت را بررسی کن.'
            )
        if code in ('LimitExceededException', 'ThrottlingException', 'TooManyRequestsException'):
            return '⏳ درخواست‌های Cost Explorer بیش از حد مجاز شده‌اند. بعداً دوباره بررسی کن.'
        return f'❌ AWS Cost Explorer: {code or "APIError"}\nاطلاعات هزینه فعلاً در دسترس نیست.'
    if isinstance(exc, (KeyError, IndexError, ValueError)):
        return ('📊 AWS گزارش قابل‌خواندنی از هزینه‌های ماه جاری برنگرداند.\n'
                '⚠️ این به معنی صفر بودن هزینه‌ها نیست؛ Billing را در کنسول بررسی کن.')
    return '❌ استعلام صورتحساب ناموفق بود. وضعیت AWS Cost Explorer و شبکه ربات را بررسی کن.'
