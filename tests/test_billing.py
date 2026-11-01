"""AWS billing presentation must not mistake missing reports for zero cost."""
from unittest.mock import Mock
from botocore.exceptions import ClientError
import pytest

from src.billing import format_billing_error, format_billing_success
from src.aws_api import monthly_cost


def aws_error(code, message='sensitive-data-must-not-appear'):
    return ClientError({'Error': {'Code': code, 'Message': message}}, 'GetCostAndUsage')


def test_unavailable_billing_is_explained_and_never_zero():
    message = format_billing_error(aws_error('DataUnavailableException'))
    assert '۲۴ ساعت' in message
    assert 'Cost Explorer' in message
    assert 'IAM' in message
    assert 'صفر دلار' in message
    assert 'sensitive-data-must-not-appear' not in message


def test_denied_billing_shows_actual_iam_action_and_scp():
    message = format_billing_error(aws_error('AccessDeniedException'))
    assert 'ce:GetCostAndUsage' in message
    assert 'SCP' in message


def test_missing_billing_period_never_invents_zero():
    session = Mock()
    session.client.return_value.get_cost_and_usage.return_value = {'ResultsByTime': []}
    with pytest.raises(ValueError, match='no billing periods'):
        monthly_cost(session)
    assert 'صفر' in format_billing_error(ValueError('missing'))


def test_valid_cost_month_remains_correct():
    session=Mock()
    session.client.return_value.get_cost_and_usage.return_value={
        'ResultsByTime':[{'Total': {'UnblendedCost': {'Amount': '4.726', 'Unit': 'USD'}}, 'Estimated': True}]
    }
    report=monthly_cost(session)
    assert report['value']=='4.726'
    assert '4.73 USD' in format_billing_success('aws1',report)
    assert 'نهایی نیست' in format_billing_success('aws1',report)
    args=session.client.return_value.get_cost_and_usage.call_args.kwargs
    assert args['Metrics']==['UnblendedCost']
    assert args['Granularity']=='MONTHLY'
    assert session.client.call_args.args == ('ce',)
