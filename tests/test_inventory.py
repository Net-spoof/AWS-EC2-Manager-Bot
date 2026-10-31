"""Account-wide EC2 inventory and price details, using fake AWS APIs only."""
import json
from decimal import Decimal
from unittest.mock import Mock

import pytest
from src.inventory import PAGE_SIZE, list_account_instances, server_page
from src.aws_api import instance_details, instance_volume_info
from src.pricing import quote_on_demand, display_quote, os_from_instance


def fake_region_client(instances):
    client=Mock()
    paginator=Mock()
    paginator.paginate.return_value=[{'Reservations':[{'Instances':instances}]}]
    client.get_paginator.return_value=paginator
    return client


def example(name, ident, ip, when):
    return {
        'InstanceId':ident, 'State':{'Name':'running'},
        'Tags':[{'Key':'Name','Value':name}], 'InstanceType':'t3.small',
        'PublicIpAddress':ip, 'LaunchTime':when,
    }


def test_all_enabled_regions_in_one_account_and_sorting():
    master=Mock()
    master.describe_regions.return_value={'Regions':[
        {'RegionName':'eu-north-1','OptInStatus':'opt-in-not-required'},
        {'RegionName':'eu-central-1','OptInStatus':'opted-in'},
        {'RegionName':'me-central-1','OptInStatus':'not-opted-in'},
    ]}
    sweden=fake_region_client([example('sweden','i-swe','13.62.52.94','2026-10-30T00:00:00+00:00')])
    germany=fake_region_client([example('germany','i-ger','1.2.3.4','2026-11-01T00:00:00+00:00')])
    sessions={'us-east-1':master,'eu-north-1':sweden,'eu-central-1':germany}
    sess=Mock()
    sess.client.side_effect=lambda service,**kwargs:sessions[kwargs.get('region_name')]
    items,failed,total=list_account_instances(sess)
    assert total==2 and failed==[]
    assert [i['name'] for i in items]==['germany','sweden']
    assert [i['region'] for i in items]==['eu-central-1','eu-north-1']
    assert items[1]['ip']=='13.62.52.94'
    assert all(i['id'] in ('i-swe','i-ger') for i in items)
    assert not any(i['region']=='me-central-1' for i in items)


def test_partial_region_errors_are_not_silenced():
    master=Mock()
    master.describe_regions.return_value={'Regions':[
        {'RegionName':'eu-north-1','OptInStatus':'opted-in'},
        {'RegionName':'eu-central-1','OptInStatus':'opted-in'},
    ]}
    ok=fake_region_client([example('ok','i-one','1.2.3.4','2026-10-31T00:00:00+00:00')])
    broken=Mock()
    broken.get_paginator.side_effect=PermissionError('denied')
    sess=Mock()
    sess.client.side_effect=lambda service,**kwargs:{
        'us-east-1':master,'eu-north-1':ok,'eu-central-1':broken
    }[kwargs.get('region_name')]
    instances,failed,total=list_account_instances(sess)
    assert total==2
    assert len(instances)==1
    assert failed==['eu-central-1']


def test_inventory_page_has_no_35_server_limit():
    items=[{'id':str(i)} for i in range(47)]
    assert PAGE_SIZE==10
    page0,total=server_page(items,0)
    last,again=server_page(items,4)
    assert total==5 and again==5
    assert [x['id'] for x in page0]==[str(i) for i in range(10)]
    assert len(last)==7
    with pytest.raises(ValueError):server_page(items,5)


def test_instance_storage_reads_real_gp3_sizes():
    ec2=Mock()
    ec2.describe_volumes.return_value={'Volumes':[
        {'VolumeId':'vol-a','Size':20,'VolumeType':'gp3'},
        {'VolumeId':'vol-b','Size':40,'VolumeType':'gp3'}
    ]}
    s=Mock()
    s.client.return_value=ec2
    info=instance_volume_info(s,'eu-north-1',['vol-a','vol-b'])
    assert info['disk_gb']==60
    assert '20 GiB gp3' in info['label']
    assert ec2.describe_volumes.call_args.kwargs['VolumeIds']==['vol-a','vol-b']
    ec2.describe_volumes.return_value['Volumes'][1]['VolumeType']='gp2'
    assert instance_volume_info(s,'eu-north-1',['vol-a','vol-b'])['disk_gb'] is None


def test_instance_details_returns_real_volume_ids_and_platform():
    ec2=Mock()
    ec2.describe_instances.return_value={'Reservations':[{'Instances':[{
        'State':{'Name':'running'},'InstanceType':'t3.small','Placement':{'AvailabilityZone':'eu-north-1a'},
        'PlatformDetails':'Linux/UNIX','BlockDeviceMappings':[
          {'DeviceName':'/dev/sda1','Ebs':{'VolumeId':'vol-a'}}
        ]
    }]}]}
    sess=Mock()
    sess.client.return_value=ec2
    r=instance_details(sess,'eu-north-1','i-example')
    assert r['volume_ids']==['vol-a']
    assert r['platform_details']=='Linux/UNIX'
    assert not r['spot']


def test_os_classification_is_conservative():
    assert os_from_instance('Linux/UNIX','linux')=='ubuntu'
    assert os_from_instance('Windows','windows')=='windows'
    assert os_from_instance('Red Hat Enterprise Linux','linux')=='rhel'
    assert os_from_instance('SUSE Linux','linux')=='suse'
    assert os_from_instance('Unknown Marketplace OS','linux') is None


def test_aws_price_without_public_ipv4_and_missing_disk():
    client=Mock()
    def product(unit,value,usage):
        return json.dumps({'product':{'attributes':{'usagetype':usage}},
          'terms':{'OnDemand':{'offer':{'priceDimensions':{
            'price':{'unit':unit,'beginRange':'0','pricePerUnit':{'USD':value}}}}}}})
    client.get_products.side_effect=[
       {'PriceList':[product('Hrs','0.08','EUN1-BoxUsage:t3.small')]},
       {'PriceList':[product('GB-Mo','0.1','EUN1-EBS:VolumeUsage.gp3')]}
    ]
    s=Mock()
    s.client.return_value=client
    q=quote_on_demand(s,'eu-north-1','t3.small',None,'ubuntu',False)
    assert q['complete'] is False
    assert Decimal(q['monthly'])==Decimal('58.4')
    assert Decimal(q['ipv4_hourly'])==0
    assert 'بدون دیسک' in display_quote(q)
