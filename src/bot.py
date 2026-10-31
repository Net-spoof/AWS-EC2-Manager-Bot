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
                      instance_details, list_instances, monthly_cost, session_for_account, validate_account,
                      valid_alias, validate_cidr)
from .storage import Store

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


async def region_menu(update,context,kind,account_id):
    try:
        account=STORE.account(account_id)
        session=await run_io(session_for_account,account)
        regions=await run_io(available_regions,session)
        if not regions: raise ValueError('No enabled regions were returned by AWS')
        context.user_data['account_id']=account_id
        rows=[]
        for i in range(0,len(regions),2):
            rows.append([(r,f'{kind}:r:{r}') for r in regions[i:i+2]])
        rows.append([('⬅️ حساب‌ها','accts')])
        await show(update,f'🌍 اکانت {account["alias"]}\nیک ریجن را انتخاب کن:',keyboard(rows))
    except Exception as exc:
        await show(update,'❌ '+error_message(exc),home_buttons())


async def list_region(update,context,region):
    account_id=context.user_data.get('account_id')
    if not account_id or region not in REGIONS: raise ValueError('Select an account and valid region first')
    account=STORE.account(account_id)
    session=await run_io(session_for_account,account)
    items=await run_io(list_instances,session,region)
    context.user_data['region']=region
    if not items:
        return await show(update,f'🖥 سروری در {region} پیدا نشد.',keyboard([[('🌍 ریجن دیگر','ls:a:'+str(account_id))],[('🏠 منو','home')]]))
    rows=[[(f"{x['state']} · {x['name'][:18]} · {x['id']}",f"i:{account_id}:{region}:{x['id']}")] for x in items[:35]]
    rows.append([('🌍 ریجن دیگر',f'ls:a:{account_id}'),('🏠 منو','home')])
    await show(update,f'🖥 {account["alias"]} / {region} — {len(items)} سرور (حداکثر ۳۵ نمایش):',keyboard(rows))


async def details(update,context,account_id,region,instance_id):
    account=STORE.account(account_id)
    session=await run_io(session_for_account,account)
    info=await run_io(instance_details,session,region,instance_id)
    text=(f"🖥 {info['name']}\nID: {info['id']}\nStatus: {info['state']}\n"
          f"Public IP: {info['ip']}\nPrivate IP: {info['private_ip']}\n"
          f"Type: {info['type']}\nRegion/AZ: {info['zone']}\nSSH key: {info['key_name']}\n"
          'User: ubuntu (for Ubuntu AMIs)')
    base=f'{account_id}:{region}:{instance_id}'
    await show(update,text,keyboard([
        [('▶️ روشن',f'act:start:{base}'),('⏸ خاموش',f'act:stop:{base}')],
        [('🔄 ری‌استارت',f'act:reboot:{base}'),('📈 CPU',f'cpu:{base}')],
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
            f"Region: {w['region']}\nUbuntu: {w['release']}\nType: {w['instance_type']}\n"
            f"Disk: {w['disk']} GiB (gp3 encrypted)\nSSH: {w['access']} / {w['ssh_cidr']}\n"
            f"{danger}\nهزینه EC2، دیسک و IPv4 عمومی طبق تعرفه AWS محاسبه می‌شود.\n"
            'با تأیید، منابع پولی AWS ایجاد می‌شوند.')


async def accept_text(update,context):
    if not await authorized(update): return
    pending=context.user_data.get('pending')
    if not pending:
        return await update.message.reply_text('از دکمه‌های منو استفاده کن. /start')
    raw=update.message.text.strip()
    if pending in ('key_id','key_secret','role_arn'):
        try: await update.message.delete()
        except TelegramError: pass  # Bot API deletion is best effort; messages are NOT end-to-end encrypted.
    try:
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
            context.user_data['wizard']['name']=raw
            context.user_data['pending']=None
            return await show(update,summarize(context.user_data['wizard']),keyboard([
                [('✅ تأیید ساخت', 'new:go')], [('❌ انصراف','home')]]))
    except Exception as exc:
        if pending in ('key_secret','role_arn'):
            context.user_data.clear()  # avoid holding secrets after failed validation
        await show(update,'❌ '+error_message(exc)+'\n/start برای شروع مجدد')


async def on_click(update:Update,context:ContextTypes.DEFAULT_TYPE):
    if not await authorized(update): return
    data=update.callback_query.data
    try:
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
        if data.startswith('new:r:'):
            region=data.split(':')[2]
            if region not in REGIONS:raise ValueError('Unsupported region')
            context.user_data['wizard']['region']=region
            return await show(update,f'🐧 نسخه Ubuntu در {region}:',keyboard([
                [('Ubuntu 22.04 LTS','new:u:22.04')], [('Ubuntu 24.04 LTS','new:u:24.04')],
                [('Ubuntu 26.04 LTS','new:u:26.04')],[('انصراف','home')]]))
        if data.startswith('new:u:'):
            context.user_data['wizard']['release']=data.split(':')[2]
            return await show(update,'⚙️ نوع EC2 (CPU/RAM) را انتخاب کن:',keyboard([
                [(f'{t} | {TYPE_SPECS[t.split(".")[1]]}',f'new:t:{t}') for t in TYPES[i:i+2]] for i in range(0,len(TYPES),2)] +
                [[('انصراف','home')]]))
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
                    f"Region: {w['region']}\nUser: ubuntu\n"
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
