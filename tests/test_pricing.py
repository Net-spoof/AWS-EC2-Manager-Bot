import json
from decimal import Decimal
from unittest.mock import Mock
import pytest
from src.pricing import quote_on_demand, display_quote, _find_ondemand_rate
from src.aws_api import region_catalog, valid_region_id
from src.regions import format_region, inactive_region_rows


def price_item(usage, unit, amount):
    item = {
        'product': {'attributes': {'usagetype': usage}},
        'terms': {'OnDemand': {'x': {'priceDimensions': {
            'y': {'unit': unit, 'beginRange': '0', 'pricePerUnit': {'USD': amount}}
        }}}},
    }
    return json.dumps(item)


def fake_session(include_disk=True, fail_price=False):
    client = Mock()
    if fail_price:
        client.get_products.side_effect = PermissionError('denied')
    else:
        first = {'PriceList': [price_item('EUN1-BoxUsage:t3.small', 'Hrs', '0.08')]}
        second = {'PriceList': [price_item('EUN1-EBS:VolumeUsage.gp3', 'GB-Mo', '0.10')]} if include_disk else {'PriceList': []}
        client.get_products.side_effect = [first, second]
    session=Mock()
    session.client.return_value=client
    return session,client


def test_full_quote_uses_live_product_price_and_monthly_baseline():
    session,client=fake_session()
    q=quote_on_demand(session,'eu-north-1','t3.small',20)
    assert q['compute_hourly']=='0.08'
    assert Decimal(q['monthly']) == Decimal('64.05')
    assert Decimal(q['hourly']) * 730 == Decimal('64.05')
    assert q['complete']
    assert '64.05' in display_quote(q)
    assert client.get_products.call_count == 2
    assert client.get_products.call_args_list[0].kwargs['ServiceCode']=='AmazonEC2'
    assert 'pricing' == session.client.call_args.args[0]


def test_incomplete_quote_is_explicit_about_missing_disk():
    session,_=fake_session(include_disk=False)
    q=quote_on_demand(session,'eu-north-1','t3.small',80)
    assert not q['complete']
    assert 'بدون دیسک' in display_quote(q)
    assert Decimal(q['monthly']) == Decimal('62.05')


def test_denied_quote_is_not_faked():
    session,_=fake_session(fail_price=True)
    with pytest.raises(PermissionError):
        quote_on_demand(session,'eu-north-1','t3.small',20)
    assert 'قابل استعلام نیست' in display_quote(None)


def test_no_matching_price_never_substitutes_fake_price():
    client=Mock()
    client.get_products.return_value={'PriceList':[price_item('EUN1-BoxUsage:t3.medium','Hrs','0.20')]}
    assert _find_ondemand_rate(client,{'regionCode':'eu-north-1'},'Hrs','BoxUsage:t3.small') is None


def test_account_region_opt_in_status_and_new_region():
    ec2=Mock()
    ec2.describe_regions.return_value={'Regions':[
        {'RegionName':'eu-north-1','OptInStatus':'opt-in-not-required'},
        {'RegionName':'me-central-1','OptInStatus':'not-opted-in'},
        {'RegionName':'ap-southeast-5','OptInStatus':'opted-in'},
        {'RegionName':'eu-new-1','OptInStatus':'opted-in'},
    ]}
    sess=Mock()
    sess.client.return_value=ec2
    enabled,disabled=region_catalog(sess)
    assert enabled == ['ap-southeast-5','eu-new-1','eu-north-1']
    assert disabled == ['me-central-1']
    assert valid_region_id('eu-new-1')
    assert format_region('eu-new-1').startswith('🌐 لوکیشن جدید AWS')
    assert 'AllRegions' in ec2.describe_regions.call_args.kwargs
    rows,pages=inactive_region_rows(disabled,'new',0)
    assert rows[0][0][1]=='new:locked:me-central-1'
    assert pages == 1



def test_stockholm_quote_uses_region_qualified_usagetype_not_region_code():
    session, client = fake_session()
    quote = quote_on_demand(session, 'eu-north-1', 't3.small', 20)
    assert quote['complete']
    call1, call2 = client.get_products.call_args_list
    filters1 = {f['Field']: f['Value'] for f in call1.kwargs['Filters']}
    filters2 = {f['Field']: f['Value'] for f in call2.kwargs['Filters']}
    assert filters1['usagetype'] == 'EUN1-BoxUsage:t3.small'
    assert filters2['usagetype'] == 'EUN1-EBS:VolumeUsage.gp3'
    assert 'regionCode' not in filters1
    assert 'regionCode' not in filters2


def test_page_two_price_is_processed():
    from src.pricing import _find_ondemand_rate
    client=Mock()
    client.get_products.side_effect=[
       {'PriceList': [], 'NextToken': 'page2'},
       {'PriceList': [price_item('EUN1-BoxUsage:t3.small','Hrs','0.0216')]}
    ]
    filters={'usagetype':'EUN1-BoxUsage:t3.small'}
    assert _find_ondemand_rate(client,filters,'Hrs','BoxUsage:t3.small') == Decimal('0.0216')
    assert client.get_products.call_args_list[1].kwargs['NextToken']=='page2'


def test_other_region_rate_is_not_accepted():
    from src.pricing import _find_ondemand_rate
    client=Mock()
    client.get_products.return_value={
        'PriceList':[price_item('EUC1-BoxUsage:t3.small','Hrs','0.024')]
    }
    assert _find_ondemand_rate(
        client,{'usagetype':'EUN1-BoxUsage:t3.small'},'Hrs','BoxUsage:t3.small'
    ) is None


def test_pricing_denied_gets_specific_help():
    from botocore.exceptions import ClientError
    from src.pricing import pricing_error_text, display_quote
    e=ClientError({'Error':{'Code':'AccessDeniedException','Message':'private server error'}},
                  'GetProducts')
    message=display_quote(None,pricing_error_text(e))
    assert 'pricing:GetProducts' in message
    assert 'AccessDeniedException' in message
    assert 'private server error' not in message


def test_unknown_region_no_cross_region_rate():
    from src.pricing import usage_codes
    with pytest.raises(ValueError,match='منطقه'):
        usage_codes('eu-unknown-25','BoxUsage:t3.small')
    assert usage_codes('eu-north-1','BoxUsage:t3.small') == ['EUN1-BoxUsage:t3.small']
