"""Persian AWS region labels for the Telegram interface.

AWS region IDs remain unchanged in callbacks and API calls. A Region's public
name indicates the AWS geography; it is not a latency or availability guarantee.
"""

REGION_LABELS = {
    'eu-central-1': '🇩🇪 آلمان — فرانکفورت',
    'eu-central-2': '🇨🇭 سوئیس — زوریخ',
    'eu-west-1': '🇮🇪 ایرلند — دوبلین',
    'eu-west-2': '🇬🇧 بریتانیا — لندن',
    'eu-west-3': '🇫🇷 فرانسه — پاریس',
    'eu-north-1': '🇸🇪 سوئد — استکهلم',
    'eu-south-1': '🇮🇹 ایتالیا — میلان',
    'eu-south-2': '🇪🇸 اسپانیا — آراگون',
    'us-east-1': '🇺🇸 آمریکا — ویرجینیای شمالی',
    'us-east-2': '🇺🇸 آمریکا — اوهایو',
    'us-west-1': '🇺🇸 آمریکا — کالیفرنیای شمالی',
    'us-west-2': '🇺🇸 آمریکا — اورگن',
    'ca-central-1': '🇨🇦 کانادا — مرکزی',
    'ap-south-1': '🇮🇳 هند — بمبئی',
    'ap-south-2': '🇮🇳 هند — حیدرآباد',
    'ap-southeast-1': '🇸🇬 سنگاپور',
    'ap-southeast-2': '🇦🇺 استرالیا — سیدنی',
    'ap-northeast-1': '🇯🇵 ژاپن — توکیو',
    'ap-northeast-2': '🇰🇷 کره جنوبی — سئول',
    'ap-northeast-3': '🇯🇵 ژاپن — اوساکا',
    'me-central-1': '🇦🇪 امارات متحده عربی',
    'me-south-1': '🇧🇭 بحرین',
    'af-south-1': '🇿🇦 آفریقای جنوبی — کیپ‌تاون',
    'ap-east-1': '🇭🇰 هنگ‌کنگ',
    'ap-east-2': '🇹🇼 تایوان — تایپه',
    'ap-southeast-3': '🇮🇩 اندونزی — جاکارتا',
    'ap-southeast-4': '🇦🇺 استرالیا — ملبورن',
    'ap-southeast-5': '🇲🇾 مالزی',
    'ap-southeast-6': '🇳🇿 نیوزیلند — اوکلند',
    'ap-southeast-7': '🇹🇭 تایلند — بانکوک',
    'ca-west-1': '🇨🇦 کانادا — کلگری',
    'il-central-1': '🇮🇱 اسرائیل — تل‌آویو',
    'mx-central-1': '🇲🇽 مکزیک — مرکزی',
    'sa-east-1': '🇧🇷 برزیل — سائوپائولو',
}

REGIONS_PER_PAGE = 8


def format_region(region):
    """Human-readable region, retaining the exact AWS ID to avoid ambiguity."""
    return f'{REGION_LABELS.get(region, "🌐 لوکیشن جدید AWS")} ({region})'


def region_button_rows(regions, kind, page):
    """Pure keyboard data: one readable button per row and compact pagination.

    The caller must use AWS available_regions() to obtain the enabled IDs.
    """
    if kind not in ('new', 'ls'):
        raise ValueError('Invalid region picker kind')
    if not regions:
        raise ValueError('No AWS regions available')
    total_pages = (len(regions) + REGIONS_PER_PAGE - 1) // REGIONS_PER_PAGE
    if page < 0 or page >= total_pages:
        raise ValueError('Invalid region picker page')
    chunk = regions[page * REGIONS_PER_PAGE:(page + 1) * REGIONS_PER_PAGE]
    rows = [[(format_region(region), f'{kind}:r:{region}')] for region in chunk]
    navigation = []
    if page > 0:
        navigation.append(('⬅️ قبلی', f'{kind}:page:{page - 1}'))
    if page + 1 < total_pages:
        navigation.append(('بعدی ➡️', f'{kind}:page:{page + 1}'))
    if navigation:
        rows.append(navigation)
    rows.append([('🏠 حساب‌ها', 'accts')])
    return rows, total_pages


def inactive_region_rows(regions, kind, page):
    """Render disabled Regions as informative choices only."""
    if kind not in ('new', 'ls') or page < 0:
        raise ValueError('Invalid region picker')
    count = max(1, (len(regions) + REGIONS_PER_PAGE - 1) // REGIONS_PER_PAGE)
    if page >= count:
        raise ValueError('Invalid page')
    chunk = regions[page * REGIONS_PER_PAGE:(page + 1) * REGIONS_PER_PAGE]
    rows = [[('🔒 ' + format_region(region), f'{kind}:locked:{region}')] for region in chunk]
    nav = []
    if page > 0:
        nav.append(('⬅️ قبلی', f'{kind}:inactive:{page-1}'))
    if page + 1 < count:
        nav.append(('بعدی ➡️', f'{kind}:inactive:{page+1}'))
    if nav:
        rows.append(nav)
    rows.append([('⬅️ بازگشت به لوکیشن‌های فعال', f'{kind}:page:0')])
    return rows, count
