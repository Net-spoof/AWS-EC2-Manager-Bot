from src.account_identity import format_identity
import pytest


def test_iam_user_sts_identity_shows_account_username_and_login_link():
    text=format_identity({'alias':'aws1','kind':'keys'}, {
        'Account':'123456789012',
        'Arn':'arn:aws:iam::123456789012:user/operations/bot-admin',
        'UserId':'AIDAEXAMPLE'
    })
    assert 'AWS Account ID: 123456789012' in text
    assert 'IAM username: bot-admin' in text
    assert 'https://123456789012.signin.aws.amazon.com/console/' in text
    assert 'ops@example.com' not in text
    assert 'رمز ورود' in text


def test_assumed_role_not_mislabeled_as_username():
    text=format_identity({'alias':'dev','kind':'role'}, {
        'Account':'123456789012',
        'Arn':'arn:aws:sts::123456789012:assumed-role/EC2Management/EC2ManagerBot'
    })
    assert 'IAM Role: EC2Management' in text
    assert 'IAM username' not in text
    assert 'این یک Role است' in text


@pytest.mark.parametrize('invalid', ['', 'abc123', '1'*13, '00000 0000000'])
def test_invalid_account_id_rejected(invalid):
    with pytest.raises(ValueError):
        format_identity({'alias':'x','kind':'keys'}, {'Account':invalid, 'Arn':''})


def test_unknown_identity_does_not_guess_username():
    text=format_identity({'alias':'a','kind':'keys'}, {
        'Account':'123456789012','Arn':'arn:aws:iam::123456789012:root'
    })
    assert 'IAM username:' not in text
    assert 'ایمیل Root' in text
