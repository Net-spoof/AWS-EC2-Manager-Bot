import pytest

from src.aws_api import REGIONS
from src.regions import REGION_LABELS, REGIONS_PER_PAGE, format_region, region_button_rows


def test_all_supported_regions_have_persian_labels_and_flags():
    assert set(REGIONS) == set(REGION_LABELS)
    for region in REGIONS:
        label = format_region(region)
        assert region in label
        assert any('\u0600' <= char <= '\u06ff' for char in label)
        assert len(label) < 64
    assert format_region('eu-central-1') == '🇩🇪 آلمان — فرانکفورت (eu-central-1)'
    assert format_region('eu-north-1') == '🇸🇪 سوئد — استکهلم (eu-north-1)'
    assert format_region('me-central-1').startswith('🇦🇪')


def test_pagination_keeps_exact_aws_region_in_callbacks():
    pages = (len(REGIONS) + REGIONS_PER_PAGE - 1) // REGIONS_PER_PAGE
    for kind in ('new', 'ls'):
        callbacks = []
        for i in range(pages):
            rows, total_pages = region_button_rows(REGIONS, kind, i)
            assert total_pages == pages
            assert all(len(row) == 1 for row in rows[:REGIONS_PER_PAGE] if row)
            callbacks.extend(callback for row in rows for label, callback in row if callback.startswith(f'{kind}:r:'))
        assert callbacks == [f'{kind}:r:{r}' for r in REGIONS]
        assert all(len(cb.encode('utf-8')) <= 64 for cb in callbacks)


def test_rejects_invalid_page_or_kind():
    for kind, page in [('new', -1), ('new', 99), ('unknown', 0)]:
        with pytest.raises(ValueError):
            region_button_rows(REGIONS, kind, page)
    with pytest.raises(ValueError):
        region_button_rows([], 'new', 0)


def test_only_enabled_aws_regions_are_shown():
    enabled=['eu-north-1','us-east-1']
    rows,pages=region_button_rows(enabled,'new',0)
    assert pages == 1
    callbacks=[cb for row in rows for _,cb in row]
    assert 'new:r:eu-north-1' in callbacks
    assert 'new:r:us-east-1' in callbacks
    assert 'new:r:ap-south-1' not in callbacks
