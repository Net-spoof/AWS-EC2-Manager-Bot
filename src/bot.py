"""Private-owner Telegram control plane for AWS EC2.

No AWS root credentials. AWS IAM API keys are deleted from chat where possible,
encrypted at rest and never included in log records. Prefer cross-account IAM roles.
"""
import asyncio
import io
import json
import logging
import os
import re
import sqlite3
from functools import partial
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from dotenv import load_dotenv
from telegram import InlineKeyboardButton as B, InlineKeyboardMarkup as K, InputFile, Update
from telegram.constants import ChatType, ParseMode
from telegram.error import BadRequest, TelegramError
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

from .aws_api import (REGIONS, TYPES, available_regions, control_instance, cpu_metric, create_instance,
                      instance_details, list_instances, monthly_cost, region_catalog, session_for_account, validate_account, valid_region_id,
                      valid_alias, validate_cidr)
from .storage import Store
from .firewall import (attached_groups, rules_for_instance, parse_port, fmt_rule,
                       is_ssh_protecting, add_port, enable_ping, disable_ping, remove_rule, public_ping_enabled)
from .ssh_password import ssh_fingerprint, change_root_password
from .regions import format_region, region_button_rows, inactive_region_rows
from .pricing import quote_on_demand, display_quote

load_dotenv()
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN','').strip()
OWNER = int(os.getenv('OWNER_TELEGRAM_ID','0'))
DATABASE_PATH = os.getenv('DATABASE_PATH','/data/accounts.sqlite3')
FERNET_KEY = os.getenv('FERNET_KEY','')
LOG_LEVEL = os.getenv('LOG_LEVEL','INFO').upper()
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s %(levelname)s %(name)s %(message)s')
log = logging.getLogger('ec2manager')
STORE = None


def keyboard(rows):
    return K([[B(label,callback_data=callback) for label,callback in row] for row in rows])


def home_buttons():
    return keyboard([
        [('🚀 ساخت سرور','new'),('🖥 سرورها','ls')],
        [('🔗 اکانت‌ها','accts'),('💰 صورتحساب','bill')],
        [('📝 فعالیت‌ها','audit'),('❓ راهنما','help')],
    ])


async def show(update, text, markup=None):
    q = update.callback_query
    if q:
        try:
            await q.edit_message_text(text, reply_markup=markup, disable_web_page_preview=True)
            return
        except (BadRequest, TelegramError):
            pass
    await update.effective_message.reply_text(text,reply_markup=markup,disable_web_page_preview=True)


async def authorized(update):
    chat = update.effective_chat
    user = update.effective_user
    if not user or user.id != OWNER or not chat or chat.type != ChatType.PRIVATE:
        if update.callback_query:
            await update.callback_query.answer('Access denied',show_alert=True)
        elif chat and chat.type==ChatType.PRIVATE:
            await update.effective_message.reply_text('⛔ این ربات خصوصی است.')
        return False
    if update.callback_query:
        await update.callback_query.answer()
    return True


def error_message(exc):
    if isinstance(exc,ClientError):
        error = exc.response.get('Error',{})
        # Show AWS error code; avoid accidentally echoing sensitive request parameters.
        return f"AWS: {error.get('Code','APIError')}"
    if isinstance(exc,NoCredentialsError):
        return 'Base AWS credentials not found on the bot host.'
    if isinstance(exc,ValueError):
        return str(exc)[:250]
    if isinstance(exc, (TimeoutError, ConnectionError, OSError)):
        return 'SSH connection failed. Check port 22, instance status and bot host network.'
    if isinstance(exc,sqlite3.IntegrityError):
        return 'Account alias already exists.'
    log.warning('AWS operation failed: %s',type(exc).__name__)
    return 'Operation failed; check IAM permissions, AWS account/region and network.'


async def run_io(fun,*args,**kwargs):
    return await asyncio.to_thread(partial(fun,*args,**kwargs))


async def command_start(update:Update,context:ContextTypes.DEFAULT_TYPE):
    if not await authorized(update): return
    context.user_data.clear()
    await show(update,'☁️ AWS EC2 Manager Bot\n\nمدیریت چند اکانت AWS و سرورهای EC2 از طریق تلگرام.\nدسترسی فقط برای مالک ربات فعال است.',home_buttons())


async def command_cancel(update:Update,context:ContextTypes.DEFAULT_TYPE):
    if not await authorized(update): return
    context.user_data.clear()
    await show(update,'✅ عملیات لغو شد.',home_buttons())


def account_keyboard(prefix,extras=None):
    rows = [[(f"{a['alias']} ({a['aws_account_id']})",f"{prefix}:{a['id']}")] for a in STORE.accounts()]
    if extras: rows += extras
    rows += [[('🏠 منو','home')]]
    return keyboard(rows)


async def account_menu(update):
    accounts=STORE.accounts()
    text=('🔗 اکانت‌های متصل:\n'+'\n'.join(f"• #{a['id']} {a['alias']} — {a['aws_account_id']} ({a['kind']})" for a in accounts)) if accounts else 'هنوز اکانتی متصل نشده است.'
    await show(update,text,keyboard([
        [('➕ اتصال با IAM Key','acc:add:keys')],
        [('➕ اتصال با IAM Role','acc:add:role')],
        [('✅ آزمایش اتصال','acctest'),('🗑 حذف اتصال','accrm')],
        [('🏠 منو','home')],
    ]))


async def show_region_page(update,context,kind,page):
    if context.user_data.get('region_kind') != kind:
        raise ValueError('انتخاب لوکیشن منقضی شده؛ دوباره اکانت را انتخاب کن.')
    account=STORE.account(context.user_data['account_id'])
    regions=context.user_data.get('region_choices',[])
    rows,total_pages=region_button_rows(regions,kind,page)
    inactive=context.user_data.get('region_inactive',[])
    if inactive:
        rows.insert(-1, [('🔒 سایر لوکیشن‌ها (نیازمند فعال‌سازی) · '+str(len(inactive)), f'{kind}:inactive:0')])
    purpose='ساخت سرور جدید' if kind=='new' else 'مشاهده سرورها'
    await show(update,f'🌍 {purpose} — اکانت {account["alias"]}\n'
                f'کشور و لوکیشن را انتخاب کن (صفحه {page+1} از {total_pages}):',keyboard(rows))


async def region_menu(update,context,kind,account_id):
    try:
        account=STORE.account(account_id)
        session=await run_io(session_for_account,account)
        regions,inactive=await run_io(region_catalog,session)
        if not regions: raise ValueError('No enabled regions were returned by AWS')
        context.user_data['account_id']=account_id
        context.user_data['region_kind']=kind
        context.user_data['region_choices']=regions
        context.user_data['region_inactive']=inactive
        await show_region_page(update,context,kind,0)
    except Exception as exc:
        await show(update,'❌ '+error_message(exc),home_buttons())


async def list_region(update,context,region):
    account_id=context.user_data.get('account_id')
    if not account_id or region not in context.user_data.get('region_choices',[]): raise ValueError('Select an enabled region first')
    account=STORE.account(account_id)
    session=await run_io(session_for_account,account)
    items=await run_io(list_instances,session,region)
    context.user_data['region']=region
    if not items:
        return await show(update,f'🖥 سروری در {format_region(region)} پیدا نشد.',keyboard([[('🌍 ریجن دیگر','ls:a:'+str(account_id))],[('🏠 منو','home')]]))
    rows=[[(f"{x['state']} · {x['name'][:18]} · {x['id']}",f"i:{account_id}:{region}:{x['id']}")] for x in items[:35]]
    rows.append([('🌍 ریجن دیگر',f'ls:a:{account_id}'),('🏠 منو','home')])
    await show(update,f'🖥 {account["alias"]} / {format_region(region)} — {len(items)} سرور (حداکثر ۳۵ نمایش):',keyboard(rows))


async def details(update,context,account_id,region,instance_id):
    account=STORE.account(account_id)
    session=await run_io(session_for_account,account)
    info=await run_io(instance_details,session,region,instance_id)
    text=(f"🖥 {info['name']}\nID: {info['id']}\nStatus: {info['state']}\n"
          f"Public IP: {info['ip']}\nPrivate IP: {info['private_ip']}\n"
          f"Type: {info['type']}\nRegion: {format_region(region)}\nAZ: {info['zone']}\nSSH key: {info['key_name']}\n"
          'User: ubuntu (for Ubuntu AMIs)')
    base=f'{account_id}:{region}:{instance_id}'
    await show(update,text,keyboard([
        [('▶️ روشن',f'act:start:{base}'),('⏸ خاموش',f'act:stop:{base}')],
        [('🔄 ری‌استارت',f'act:reboot:{base}'),('📈 CPU',f'cpu:{base}')],
        [('🛡 فایروال و Ping',f'fw:open:{base}')],
        [('🔐 تغییر رمز Root',f'pw:open:{base}')],
        [('🗑 حذف سرور',f'del1:{base}')],
        [('⬅️ بازگشت',f'ls:r:{region}')],
    ]))


TYPE_SPECS = {
    'micro': '2 vCPU / 1 GiB', 'small': '2 vCPU / 2 GiB',
    'medium': '2 vCPU / 4 GiB', 'large': '2 vCPU / 8 GiB',
    'xlarge': '4 vCPU / 16 GiB', '2xlarge': '8 vCPU / 32 GiB'
}

def summarize(w):
    danger='⚠️ SSH برای کل اینترنت باز است!' if w.get('ssh_cidr')=='0.0.0.0/0' else ''
    return (f"☁️ پیش‌نمایش ساخت:\nنام: {w['name']}\nAccount ID: {w['account_id']}\n"
            f"Region: {format_region(w['region'])}\nUbuntu: {w['release']}\nType: {w['instance_type']}\n"
            f"Disk: {w['disk']} GiB (gp3 encrypted)\nSSH: {w['access']} / {w['ssh_cidr']}\n"
            f"{danger}\n\n{display_quote(w.get('quote'))}\n\n"
            'با تأیید، منابع پولی AWS ایجاد می‌شوند.')




def fw_context(context):
    state=context.user_data.get('fw')
    if not state or not all(k in state for k in ('account_id','region','instance_id','group_id')):
        raise ValueError('Firewall session expired. Open the server again.')
    return state


async def firewall_screen(update,context):
    w=fw_context(context)
    account=STORE.account(w['account_id'])
    sess=await run_io(session_for_account,account)
    rules=await run_io(rules_for_instance,sess,w['region'],w['instance_id'],w['group_id'])
    ping=public_ping_enabled(rules)
    lines=[f"🛡 فایروال EC2 / {w['instance_id']}",f"Security Group: {w['group_id']}",
           f"Ping عمومی: {'✅ فعال' if ping else '❌ غیرفعال'}",
           'قوانین Security Group ممکن است روی سرورهای دیگر هم تأثیر بگذارند.',
           'قوانین ورودی:']
    lines += [f"• {fmt_rule(r)}" for r in rules[:24]] or ['• هیچ قانونی وجود ندارد']
    if len(rules)>24: lines.append(f'... و {len(rules)-24} قانون دیگر')
    rows=[[('🔕 غیرفعال کردن Ping','fw:pingoff') if ping else ('✅ فعال کردن Ping','fw:pingon')],
          [('➕ پورت TCP','fw:add:tcp'),('➕ پورت UDP','fw:add:udp')],
          [('🔄 بروزرسانی','fw:refresh')]]
    for r in rules[:20]:
        if not is_ssh_protecting(r):
            rid=r.get('SecurityGroupRuleId')
            if rid:
                rows.append([(f'🗑 {fmt_rule(r)[:37]}',f'fw:rm:{rid}')])
    rows.append([('⬅️ سرور',f"i:{w['account_id']}:{w['region']}:{w['instance_id']}")])
    await show(update,'\n'.join(lines),keyboard(rows))


def _ssh_state(context):
    state=context.user_data.get('ssh_change')
    if not state or not all(k in state for k in ('account_id','region','instance_id','ip','fingerprint')):
        raise ValueError('SSH session expired. Start again from server details.')
    return state

async def accept_text(update,context):
    if not await authorized(update): return
    pending=context.user_data.get('pending')
    if not pending:
        return await update.message.reply_text('از دکمه‌های منو استفاده کن. /start')
    raw=update.message.text.strip()
    if pending in ('key_id','key_secret','role_arn','pw_current'):
        try: await update.message.delete()
        except TelegramError: pass  # Bot API deletion is best effort; messages are NOT end-to-end encrypted.
    try:
        if pending=='fw_port':
            w=fw_context(context)
            w['port_start'],w['port_end']=parse_port(raw)
            context.user_data['pending']='fw_cidr'
            return await show(update,'🌐 محدوده IPv4 مجاز را بفرست، مثل `203.0.113.5/32` یا `0.0.0.0/0`.\nبرای SSH محدوده عمومی مجاز نیست.')
        if pending=='fw_cidr':
            w=fw_context(context)
            w['cidr']=validate_cidr(raw)
            context.user_data['pending']=None
            warning='⚠️ این پورت برای کل اینترنت باز خواهد شد.\n' if w['cidr']=='0.0.0.0/0' else ''
            return await show(update,f"{warning}تأیید باز کردن {w['protocol'].upper()} {w['port_start']}-{w['port_end']} برای {w['cidr']} در {w['group_id']}؟", keyboard([
                [('✅ تأیید افزودن قانون','fw:go')],[('لغو','fw:refresh')]]))
        if pending=='pw_current':
            if not 1 <= len(raw) <= 256:
                context.user_data.clear()
                raise ValueError('Current password length is invalid')
            w=_ssh_state(context)
            context.user_data.clear()
            # Credentials live only for this single operation, never in sqlite/logs.
            await context.bot.send_message(chat_id=update.effective_chat.id,text='🔐 در حال بررسی SSH و تغییر رمز Root...')
            new_pw=await run_io(change_root_password,w['ip'],raw,w['fingerprint'])
            STORE.log(w['account_id'],'change_root_password',w['region'],w['instance_id'])
            return await context.bot.send_message(chat_id=update.effective_chat.id,
                text=f"✅ رمز Root در سرور {w['instance_id']} تغییر کرد.\nIP: {w['ip']}\nUser: root\nرمز جدید (فقط همین بار):\n{new_pw}\n\n⚠️ این پیام شامل رمز محرمانه است. آن را در جای امن نگه دار و از چت حذف کن.",
                reply_markup=home_buttons())
        if pending in ('alias_keys','alias_role'):
            if not valid_alias(raw): raise ValueError('نام اکانت باید ۲ تا ۳۲ کاراکتر لاتین، عدد یا _ و - باشد.')
            context.user_data['alias']=raw
            if pending=='alias_keys':
                context.user_data['pending']='key_id'
                return await show(update,'🔑 AWS IAM Access Key ID را بفرست. پیام را پس از دریافت حذف می‌کنم (تا حد امکان).')
            context.user_data['pending']='role_arn'
            return await show(update,'🔗 Role ARN معتبر را بفرست. حساب میزبان ربات باید مجوز sts:AssumeRole داشته باشد.')
        if pending=='key_id':
            if not re.fullmatch(r'[A-Z0-9]{16,32}',raw): raise ValueError('Access Key ID format is invalid')
            context.user_data['access_key']=raw
            context.user_data['pending']='key_secret'
            return await show(update,'🔐 Secret Access Key را بفرست. فقط در گفت‌وگوی خصوصی با ربات.')
        if pending=='key_secret':
            if len(raw)<20: raise ValueError('Secret Access Key is too short')
            payload={'access_key':context.user_data['access_key'],'secret_key':raw}
            aws_account=await run_io(validate_account,'keys',payload)
            STORE.add_account(context.user_data['alias'],'keys',json.dumps(payload),aws_account)
            context.user_data.clear()
            return await show(update,f'✅ اکانت AWS {aws_account} اضافه شد.\nتوجه: کلید IAM در تلگرام ارسال شد؛ روش IAM Role امن‌تر است.',home_buttons())
        if pending=='role_arn':
            if not re.fullmatch(r'arn:aws(-[\w]+)?:iam::\d{12}:role/[\w+=,.@/-]{1,200}',raw):
                raise ValueError('Role ARN is invalid')
            payload={'role_arn':raw}
            aws_account=await run_io(validate_account,'role',payload)
            STORE.add_account(context.user_data['alias'],'role',json.dumps(payload),aws_account)
            context.user_data.clear()
            return await show(update,f'✅ IAM Role برای اکانت {aws_account} فعال شد.',home_buttons())
        if pending=='ssh_cidr':
            cidr=validate_cidr(raw)
            context.user_data['wizard']['ssh_cidr']=cidr
            context.user_data['pending']='instance_name'
            return await show(update,'✍️ نام سرور را بنویس (۳ تا ۴۰ حرف لاتین، عدد، خط تیره یا زیرخط).')
        if pending=='instance_name':
            if not re.fullmatch(r'[A-Za-z0-9_-]{3,40}',raw):
                raise ValueError('Server name must contain 3–40 Latin letters, digits, _ or -')
            w=context.user_data['wizard']
            w['name']=raw
            context.user_data['pending']=None
            await show(update,'💵 در حال دریافت قیمت رسمی AWS برای این لوکیشن و مشخصات...')
            try:
                acct=STORE.account(w['account_id'])
                sess=await run_io(session_for_account,acct)
                w['quote']=await run_io(quote_on_demand,sess,w['region'],w['instance_type'],w['disk'])
            except Exception as exc:
                log.warning('Pricing API unavailable: %s', type(exc).__name__)
                w['quote']=None
            return await show(update,summarize(w),keyboard([
                [('✅ تأیید ساخت', 'new:go')], [('❌ انصراف','home')]]))
    except Exception as exc:
        if pending in ('key_secret','role_arn','pw_current'):
            context.user_data.clear()  # avoid holding secrets after failed validation
        await show(update,'❌ '+error_message(exc)+'\n/start برای شروع مجدد')


async def on_click(update:Update,context:ContextTypes.DEFAULT_TYPE):
    if not await authorized(update): return
    data=update.callback_query.data
    try:
        if data.startswith('fw:open:'):
            _,_,aid,region,iid=data.split(':')
            account=STORE.account(int(aid))
            sess=await run_io(session_for_account,account)
            groups=await run_io(attached_groups,sess,region,iid)
            if not groups: raise ValueError('No Security Group attached to this server')
            context.user_data.clear()
            context.user_data['fw']={'account_id':int(aid),'region':region,'instance_id':iid}
            rows=[[(f"{g['name']} · {g['id']}",f"fw:sg:{g['id']}")] for g in groups]
            rows.append([('⬅️ سرور',f'i:{aid}:{region}:{iid}')])
            return await show(update,'🛡 Security Group موردنظر را انتخاب کن.\nتغییرات SG ممکن است روی سرورهای دیگری هم اعمال شود.',keyboard(rows))
        if data.startswith('fw:sg:'):
            w=context.user_data.get('fw')
            if not w: raise ValueError('Select the server first')
            group_id=data.split(':')[2]
            account=STORE.account(w['account_id']);sess=await run_io(session_for_account,account)
            groups=await run_io(attached_groups,sess,w['region'],w['instance_id'])
            if group_id not in [g['id'] for g in groups]: raise ValueError('Group not attached to selected server')
            w['group_id']=group_id
            return await firewall_screen(update,context)
        if data=='fw:refresh':
            context.user_data['pending']=None
            return await firewall_screen(update,context)
        if data=='fw:pingon':
            w=fw_context(context);account=STORE.account(w['account_id'])
            sess=await run_io(session_for_account,account)
            changed=await run_io(enable_ping,sess,w['region'],w['instance_id'],w['group_id'])
            if changed: STORE.log(w['account_id'],'enable_ping',w['region'],w['group_id'])
            return await firewall_screen(update,context)
        if data=='fw:pingoff':
            w=fw_context(context)
            return await show(update,'⚠️ درخواست حذف قانون Ping عمومی از Security Group.\nاین تغییر ممکن است چند EC2 را تحت تأثیر قرار دهد.',keyboard([
                [('✅ تأیید حذف Ping','fw:pingoffgo')],[('لغو','fw:refresh')]]))
        if data=='fw:pingoffgo':
            w=fw_context(context);account=STORE.account(w['account_id'])
            sess=await run_io(session_for_account,account)
            removed=await run_io(disable_ping,sess,w['region'],w['instance_id'],w['group_id'])
            if removed: STORE.log(w['account_id'],'disable_ping',w['region'],w['group_id'])
            return await firewall_screen(update,context)
        if data.startswith('fw:add:'):
            proto=data.split(':')[2]
            if proto not in ('tcp','udp'): raise ValueError('Unsupported protocol')
            w=fw_context(context)
            w['protocol']=proto
            for k in ('port_start','port_end','cidr'):w.pop(k,None)
            context.user_data['pending']='fw_port'
            return await show(update,f'🔌 شماره پورت {proto.upper()} را بفرست. مثال: `443` یا `10000-10010`.')
        if data=='fw:go':
            w=fw_context(context)
            if not all(k in w for k in ('protocol','port_start','port_end','cidr')):
                raise ValueError('Incomplete port wizard')
            context.user_data['pending']=None
            account=STORE.account(w['account_id']);sess=await run_io(session_for_account,account)
            await run_io(add_port,sess,w['region'],w['instance_id'],w['group_id'],w['protocol'],w['port_start'],w['port_end'],w['cidr'])
            STORE.log(w['account_id'],'add_port',w['region'],w['group_id'])
            for k in ('protocol','port_start','port_end','cidr'):w.pop(k,None)
            return await firewall_screen(update,context)
        if data.startswith('fw:rm:'):
            rid=data.split(':')[2];w=fw_context(context)
            account=STORE.account(w['account_id']);sess=await run_io(session_for_account,account)
            rules=await run_io(rules_for_instance,sess,w['region'],w['instance_id'],w['group_id'])
            matches=[r for r in rules if r.get('SecurityGroupRuleId')==rid]
            if not matches or is_ssh_protecting(matches[0]):raise ValueError('Cannot remove this rule')
            return await show(update,f'⚠️ این قانون حذف شود؟\n{fmt_rule(matches[0])}\n{rid}',keyboard([
                [('🗑 تأیید حذف قانون',f'fw:rmok:{rid}')],[('لغو','fw:refresh')]]))
        if data.startswith('fw:rmok:'):
            rid=data.split(':')[2];w=fw_context(context)
            account=STORE.account(w['account_id']);sess=await run_io(session_for_account,account)
            await run_io(remove_rule,sess,w['region'],w['instance_id'],w['group_id'],rid)
            STORE.log(w['account_id'],'remove_rule',w['region'],rid)
            return await firewall_screen(update,context)
        if data.startswith('pw:open:'):
            _,_,aid,region,iid=data.split(':')
            account=STORE.account(int(aid));sess=await run_io(session_for_account,account)
            info=await run_io(instance_details,sess,region,iid)
            if info['state']!='running': raise ValueError('Server must be running to change password')
            if info['ip']=='—': raise ValueError('Server has no public IPv4')
            fingerprint=await run_io(ssh_fingerprint,info['ip'])
            context.user_data.clear()
            context.user_data['ssh_change']={'account_id':int(aid),'region':region,'instance_id':iid,
                                             'ip':info['ip'],'fingerprint':fingerprint}
            return await show(update,f"🔐 تغییر رمز Root با SSH\nIP: {info['ip']}\nاثر انگشت کلید سرور:\n{fingerprint}\n\nاین اثر انگشت را با خروجی `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` روی همان سرور مقایسه کن.\n⚠️ پس از تأیید، رمز فعلی Root از طریق چت خصوصی ربات درخواست می‌شود. Telegram رمزنگاری سرتاسری ندارد.\nربات رمز فعلی را نگهداری نمی‌کند؛ رمز جدید تصادفی می‌سازد.", keyboard([
                [('✅ اثر انگشت را بررسی و تأیید کردم','pw:trust')],
                [('انصراف','home')]]))
        if data=='pw:trust':
            _ssh_state(context)
            context.user_data['pending']='pw_current'
            return await show(update,'🔑 رمز فعلی کاربر Root را بفرست.\nربات تلاش می‌کند پیام حاوی رمز را پس از دریافت حذف کند؛ پیام‌های ربات End-to-End نیستند.')
        if data=='home':
            context.user_data.clear()
            return await show(update,'☁️ منوی اصلی',home_buttons())
        if data=='help':
            return await show(update,'❓ راهنما:\n1) اکانت AWS را با IAM Role یا کلید محدود IAM وصل کن.\n2) ساخت سرور: حساب، ریجن، Ubuntu، مشخصات، فضای دیسک و نوع ورود.\n3) در سرورها وضعیت و IP را ببین، روشن/خاموش کن یا حذف کن.\n\nبرای توقف عملیات /cancel را بزن.\nاستفاده از AWS هزینه واقعی دارد.',home_buttons())
        if data=='audit':
            rows=STORE.recent()
            text='📝 فعالیت‌های اخیر:\n'+'\n'.join(f"{r['created_at']} | {r['operation']} | {r['region']} | {r['resource']}" for r in rows)
            return await show(update,text if rows else 'تاکنون فعالیتی ثبت نشده است.',home_buttons())
        if data=='accts': return await account_menu(update)
        if data.startswith('acc:add:'):
            kind=data.split(':')[2]
            if kind not in ('keys','role'): raise ValueError('Invalid account type')
            context.user_data.clear()
            context.user_data['pending']='alias_'+kind
            warning=('⚠️ کلید IAM را به هیچ عنوان از کاربر Root نساز. ارسال رمز از طریق ربات تلگرام پایان‌به‌پایان رمزنگاری نمی‌شود.\n\n'
                     if kind=='keys' else '✅ اتصال از طریق Role امن‌تر است و کلید ثابتی به ربات ارسال نمی‌شود.\n\n')
            return await show(update,warning+'نام کوتاه برای اکانت بنویس (مثال: aws1).')
        if data=='acctest': return await show(update,'برای تست اکانت انتخاب کن:',account_keyboard('test'))
        if data.startswith('test:'):
            aid=int(data.split(':')[1]); account=STORE.account(aid)
            sess=await run_io(session_for_account,account)
            identity=await run_io(lambda:sess.client('sts').get_caller_identity())
            return await show(update,f'✅ اکانت {account["alias"]}\nAWS Account: {identity["Account"]}',home_buttons())
        if data=='accrm':return await show(update,'⚠️ اتصال کدام اکانت حذف شود؟ سرورهای AWS حذف نمی‌شوند.',account_keyboard('rm'))
        if data.startswith('rm:'):
            aid=int(data.split(':')[1]); account=STORE.account(aid)
            return await show(update,f'حذف اتصال {account["alias"]}؟',keyboard([
                [('بله، حذف اتصال',f'rmyes:{aid}')],[('انصراف','accts')]]))
        if data.startswith('rmyes:'):
            aid=int(data.split(':')[1]); STORE.remove_account(aid)
            return await show(update,'✅ اتصال حذف شد؛ هیچ EC2 حذف نشده است.',home_buttons())
        if data in ('new','ls','bill'):
            if not STORE.accounts():return await show(update,'ابتدا یک اکانت AWS متصل کن.',keyboard([[('🔗 اتصال اکانت','accts')]]))
            context.user_data.clear()
            if data=='new': context.user_data['wizard']={}
            return await show(update,'🔗 اکانت را انتخاب کن:',account_keyboard(f'{data}:a'))
        if data.startswith('new:a:'):
            aid=int(data.split(':')[2]); context.user_data['wizard']={'account_id':aid}
            return await region_menu(update,context,'new',aid)
        if data.startswith('ls:a:'):
            aid=int(data.split(':')[2]);return await region_menu(update,context,'ls',aid)
        if data.startswith('bill:a:'):
            aid=int(data.split(':')[2]); account=STORE.account(aid)
            sess=await run_io(session_for_account,account)
            info=await run_io(monthly_cost,sess)
            return await show(update,f"💰 هزینه ماه جاری {account['alias']}: {float(info['value']):.2f} {info['currency']}\n"
                                     'Cost Explorer با تأخیر به‌روزرسانی می‌شود؛ هزینه نهایی یا هزینه هر VPS نیست.',home_buttons())
        if data.startswith(('new:page:', 'ls:page:')):
            kind,_,page=data.split(':')
            return await show_region_page(update,context,kind,int(page))
        if data.startswith(('new:inactive:', 'ls:inactive:')):
            kind,_,page=data.split(':')
            if kind!=context.user_data.get('region_kind'):
                raise ValueError('انتخاب لوکیشن منقضی شده است')
            rows,total=inactive_region_rows(context.user_data.get('region_inactive',[]),kind,int(page))
            return await show(update,f'🔒 لوکیشن‌های غیرفعال در اکانت تو — صفحه {int(page)+1}/{total}\n'
                              'برای استفاده باید از AWS Console → Account → AWS Regions فعال شوند.\n'
                              'برای این کار دسترسی مدیریتی اکانت لازم است؛ ربات آن‌ها را خودکار فعال نمی‌کند.',keyboard(rows))
        if data.startswith(('new:locked:', 'ls:locked:')):
            kind,_,region=data.split(':')
            if kind!=context.user_data.get('region_kind') or region not in context.user_data.get('region_inactive',[]):
                raise ValueError('لوکیشن نامعتبر است')
            return await show(update,f'🔒 {format_region(region)} هنوز در اکانت AWS فعال نیست.\n'
                              'در AWS Console روی نام اکانت → Account → AWS Regions برو و این لوکیشن را Enable کن.\n'
                              'بعد از تکمیل فعال‌سازی دوباره منوی لوکیشن ربات را باز کن.',
                              keyboard([[('⬅️ لوکیشن‌های غیرفعال',f'{kind}:inactive:0')],
                                        [('🏠 منو','home')]]))
        if data.startswith('new:r:'):
            region=data.split(':')[2]
            if not valid_region_id(region) or region not in context.user_data.get('region_choices',[]):
                raise ValueError('لوکیشن معتبر نیست؛ دوباره اکانت را انتخاب کن.')
            context.user_data['wizard']['region']=region
            return await show(update,f'🐧 نسخه Ubuntu در {format_region(region)}:',keyboard([
                [('Ubuntu 22.04 LTS','new:u:22.04')], [('Ubuntu 24.04 LTS','new:u:24.04')],
                [('Ubuntu 26.04 LTS','new:u:26.04')],[('انصراف','home')]]))
        if data.startswith('new:u:'):
            context.user_data['wizard']['release']=data.split(':')[2]
            return await show(update,'⚙️ مشخصات CPU و RAM را انتخاب کن\nهر گزینه در یک سطر:',keyboard(
                [[(f'🖥 {t} · {TYPE_SPECS[t.split(".")[1]]}',f'new:t:{t}')] for t in TYPES] +
                [[('❌ انصراف','home')]]))
        if data.startswith('new:t:'):
            choice=data.split(':')[2]
            if choice not in TYPES:raise ValueError('Invalid instance type')
            context.user_data['wizard']['instance_type']=choice
            return await show(update,'💽 دیسک EBS gp3:',keyboard([
                [('20 GiB','new:d:20'),('40 GiB','new:d:40')],
                [('80 GiB','new:d:80'),('160 GiB','new:d:160')],
                [('انصراف','home')]]))
        if data.startswith('new:d:'):
            context.user_data['wizard']['disk']=int(data.split(':')[2])
            return await show(update,'🔐 روش ورود Ubuntu با کاربر ubuntu:\nکلید SSH امنیت بیشتری دارد. رمز عبور در Telegram نمایش داده می‌شود و پس از ساخت مجدد قابل بازیابی نیست.',
                keyboard([[('🔑 SSH Key (پیشنهادی)','new:m:key')],[('🔒 رمز عبور SSH','new:m:password')],[('انصراف','home')]]))
        if data.startswith('new:m:'):
            mode=data.split(':')[2]
            if mode not in ('key','password'):raise ValueError('Invalid access mode')
            context.user_data['wizard']['access']=mode
            context.user_data['pending']='ssh_cidr'
            return await show(update,'🌐 محدوده مجاز SSH را بفرست، مثل `198.51.100.10/32`.\n'
                'باز کردن برای همه: `0.0.0.0/0` (ریسک حمله و اسکن دارد).\n'
                'این مقدار بعداً در AWS Security Groups قابل تغییر است.')
        if data=='new:go':
            w=context.user_data.get('wizard',{})
            required={'account_id','region','release','instance_type','disk','access','ssh_cidr','name'}
            if not required.issubset(w):raise ValueError('Incomplete creation wizard')
            # Clear immediately to prevent a second click creating another chargeable server.
            context.user_data.clear()
            await show(update,'⏳ درخواست ساخت به AWS ارسال شد؛ نتیجه پس از پاسخ API نمایش داده می‌شود.')
            account=STORE.account(w['account_id'])
            sess=await run_io(session_for_account,account)
            result=await run_io(create_instance,sess,w['region'],w['name'],w['release'],
                                w['instance_type'],w['disk'],w['ssh_cidr'],w['access'])
            STORE.log(w['account_id'],'create',w['region'],result['id'])
            output=(f"✅ سرور ایجاد شد.\nAccount: {account['alias']}\nInstance ID: {result['id']}\n"
                    f"Region: {format_region(w['region'])}\nUser: ubuntu\n\n"
                    f"{display_quote(w.get('quote'))}\n\n"
                    'IP عمومی ممکن است چند لحظه بعد اختصاص داده شود. از «سرورها» بررسی کن.\n'
                    'ورود SSH فقط پس از تکمیل cloud-init آماده خواهد بود.')
            await update.effective_message.reply_text(output,reply_markup=home_buttons())
            if result['password']:
                await update.effective_message.reply_text(f"🔒 رمز SSH (فقط همین بار نمایش داده می‌شود):\n{result['password']}\n"
                    'پس از اتصال، آن را عوض کن. ورود با رمز ممکن است تا تکمیل cloud-init زمان ببرد.')
            if result['pem']:
                pem=io.BytesIO(result['pem'].encode());pem.name=result['key_name']+'.pem'
                await update.effective_message.reply_document(InputFile(pem,filename=pem.name),
                        caption='🔑 کلید خصوصی SSH؛ فقط یک بار ارسال می‌شود. آن را محرمانه نگه دار و chmod 600 بزن.')
            return
        if data.startswith('ls:r:'):
            return await list_region(update,context,data.split(':')[2])
        if data.startswith('i:'):
            _,aid,region,iid=data.split(':')
            return await details(update,context,int(aid),region,iid)
        if data.startswith('cpu:'):
            _,aid,region,iid=data.split(':')
            account=STORE.account(int(aid)); sess=await run_io(session_for_account,account)
            cpu=await run_io(cpu_metric,sess,region,iid)
            return await show(update,f'📈 CPU متوسط آخرین پنجره ۵ دقیقه‌ای: {cpu if cpu is not None else "داده موجود نیست"}%\nInstance: {iid}',
                              keyboard([[('⬅️ سرور',f'i:{aid}:{region}:{iid}')]]))
        if data.startswith('act:'):
            _,action,aid,region,iid=data.split(':')
            if action not in ('start','stop','reboot'):raise ValueError('Unsupported action')
            account=STORE.account(int(aid));sess=await run_io(session_for_account,account)
            await run_io(control_instance,sess,region,iid,action)
            STORE.log(int(aid),action,region,iid)
            return await show(update,f'✅ درخواست {action} برای {iid} ثبت شد.',
                              keyboard([[('⬅️ سرور',f'i:{aid}:{region}:{iid}')]]))
        if data.startswith('del1:'):
            _,aid,region,iid=data.split(':')
            return await show(update,f'⚠️ حذف EC2 {iid} در {region} برگشت‌ناپذیر است.\n'
                'داده‌های EBS با DeleteOnTermination حذف می‌شوند. منابع جداگانه مثل Elastic IP، Security Group و Key Pair ممکن است باقی بمانند.\n'
                'آیا برای ورود به مرحله تأیید نهایی مطمئنی؟',keyboard([
                [('مرحله دوم تأیید',f'del2:{aid}:{region}:{iid}')],
                [('لغو',f'i:{aid}:{region}:{iid}')]]))
        if data.startswith('del2:'):
            _,aid,region,iid=data.split(':')
            return await show(update,f'🛑 تأیید نهایی حذف {iid}\nاین کار سرور را terminate می‌کند و قابل بازگشت نیست.',keyboard([
                [('🗑 بله، حذف قطعی',f'delgo:{aid}:{region}:{iid}')],
                [('انصراف',f'i:{aid}:{region}:{iid}')]]))
        if data.startswith('delgo:'):
            _,aid,region,iid=data.split(':')
            account=STORE.account(int(aid));sess=await run_io(session_for_account,account)
            await run_io(control_instance,sess,region,iid,'terminate')
            STORE.log(int(aid),'terminate',region,iid)
            return await show(update,f'✅ درخواست Terminate برای {iid} ثبت شد.\n'
               'منابع جانبی را در AWS بررسی کن تا هزینه ناخواسته باقی نماند.',home_buttons())
        return await show(update,'درخواست نامعتبر. /start',home_buttons())
    except Exception as exc:
        await show(update,'❌ '+error_message(exc)+'\nبرای برگشت: /start',home_buttons())


async def error_handler(update: object,context:ContextTypes.DEFAULT_TYPE):
    log.error('Unhandled error type: %s',type(context.error).__name__ if context.error else 'unknown')
    if isinstance(update,Update) and update.effective_user and update.effective_user.id==OWNER:
        try: await update.effective_message.reply_text('❌ خطای داخلی رخ داد؛ لاگ سرویس را بررسی کن.')
        except Exception: pass


def main():
    global STORE
    if not TOKEN or OWNER<=0 or not FERNET_KEY:
        raise SystemExit('Set TELEGRAM_BOT_TOKEN, OWNER_TELEGRAM_ID and FERNET_KEY in .env')
    STORE=Store(DATABASE_PATH,FERNET_KEY)
    app=Application.builder().token(TOKEN).concurrent_updates(False).build()
    app.add_handler(CommandHandler('start',command_start))
    app.add_handler(CommandHandler('cancel',command_cancel))
    app.add_handler(CallbackQueryHandler(on_click))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND,accept_text))
    app.add_error_handler(error_handler)
    log.info('Bot started. Owner ID configured; credentials never logged.')
    app.run_polling(drop_pending_updates=True,allowed_updates=['message','callback_query'])


if __name__=='__main__':main()
