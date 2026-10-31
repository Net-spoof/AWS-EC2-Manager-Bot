# ☁️ AWS EC2 Manager Bot

**Private, Persian-language Telegram control plane for multiple AWS accounts.**

A pragmatic owner-only implementation for provisioning Ubuntu EC2 instances and operating existing EC2 servers. Supports multiple IAM key connections encrypted on disk, or AWS cross-account `AssumeRole` connections without transferring account API secrets through Telegram.

> ⚠️ This project is provided as a deployable **initial release**, not a production-certified cloud control plane. It has not been tested against a live AWS account from this environment. AWS resources incur real charges. Start with an account/budget dedicated to testing.

## Features

| Feature | Included |
| --- | --- |
| Persian Telegram menus, owner-only private chat access | ✅ |
| Add/remove/test multiple AWS IAM access key accounts | ✅ |
| Add/remove/test multiple AssumeRole accounts | ✅ |
| AWS-enabled Region picker | ✅ |
| EC2 create in default VPC with Ubuntu 22.04 / 24.04 / 26.04 | ✅ |
| t3 and t3a x86 instance choices, gp3 encrypted root disk | ✅ |
| SSH access via auto-generated .pem key or random password | ✅ |
| Adjustable SSH firewall CIDR | ✅ |
| List existing EC2 instances in selected account & Region | ✅ |
| Show IP, status, type, start/stop/reboot and CPU average | ✅ |
| Two-stage terminate confirmation | ✅ |
| Current-month AWS Cost Explorer estimate and audit log | ✅ |
| Docker Compose, GitHub CI, sample IAM policy, tests | ✅ |
| Automatic Elastic IP allocation and dedicated VPC construction | ❌ (not in this release) |
| Automatic removal of orphaned Security Groups/Key Pairs | ❌ (manual AWS cleanup) |
| Automatic recurring cost alerts | ❌ (use AWS Budgets) |

## 1. GitHub repository

This is the source repository: [Net-spoof/AWS-EC2-Manager-Bot](https://github.com/Net-spoof/AWS-EC2-Manager-Bot). Never commit `.env`, keys, SQLite databases, or bot tokens.

## 2. Prerequisites

- Ubuntu 22.04 / 24.04 / 26.04 VPS with Internet access to Telegram and AWS endpoints.
- Docker Engine with `docker compose` (Docker Compose v2).
- Telegram bot from [@BotFather](https://t.me/BotFather) and your numeric Telegram user ID.
- At least one AWS IAM user **with limited permissions**, or a trusted IAM Role. **Never use root access keys.**
- AWS default VPC + default subnet in the target Region, and sufficient EC2 quotas.

### AWS permissions

For a dedicated IAM user, attach and review [`deploy/iam-ec2-manager-policy.json`](deploy/iam-ec2-manager-policy.json). This example policy permits EC2 create and terminate within the account; **its EC2 write permissions are account-wide**. Restrict resources, tags, VPCs, permitted Regions and instance families as appropriate for production use. `sts:GetCallerIdentity` does not normally require an explicit IAM Allow policy. Cost Explorer may need to be enabled. IAM roles for cross-account access need an appropriate trust relationship allowing the bot's **base IAM principal** to call `sts:AssumeRole` as well as permissions to operate EC2 in the destination account.

**Multi-account choices:**

A. `IAM Key` — easiest to set up: create a dedicated IAM Access Key in AWS, open the bot's private chat, choose “اتصال با IAM Key”, enter a nickname, then paste Access Key ID and Secret Access Key. Messages are deleted on a best-effort basis; **Telegram bot conversations are not end-to-end encrypted.** Keys are Fernet-encrypted in SQLite but remain accessible to the bot process. Rotate keys periodically and do not use AWS root credentials.

B. `AssumeRole` — recommended: run the bot on an AWS host with an instance role (or give the host base AWS credentials via environment). Configure an IAM cross-account role in each AWS account with an AWS trust policy for the base IAM principal, permissions in the sample policy, then add each Role ARN from Telegram. The bot obtains temporary credentials using STS. Do **not** send passwords/secret keys via Telegram.

## 3. Install / run

**Quick setup (interactive):** Clone this repository, run `bash scripts/install.sh` and follow the terminal prompts. The script expects Docker Engine, Compose v2, and Python 3 to be installed. Do not paste tokens into issue reports.

**Manual setup:**

```bash
sudo apt update
sudo apt install -y git docker.io docker-compose-plugin python3 python3-venv
sudo systemctl enable --now docker
# Clone your own new GitHub repository after uploading these files:
git clone https://github.com/Net-spoof/AWS-EC2-Manager-Bot.git
cd AWS-EC2-Manager-Bot
cp .env.example .env
python3 -m venv .venv
. .venv/bin/activate
python -c 'import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())'
# Paste that generated Fernet key into .env (FERNET_KEY=...)
# Set TELEGRAM_BOT_TOKEN=... and OWNER_TELEGRAM_ID=... in .env
chmod 600 .env
sudo docker compose up -d --build
sudo docker compose logs --tail=60 --follow
```

Note: Some Ubuntu distributions use the official Docker repository rather than an `apt` `docker-compose-plugin` package. In that case follow Docker's official installation instructions. Do **not** rely on Docker image defaults for firewall isolation: the bot exposes **no inbound ports**.

**Uninstall/restart:** `sudo docker compose down` stops the bot and retains the named encrypted account database volume; `sudo docker compose up -d --build` updates it. Removing `-v` in `docker compose down -v` permanently destroys that database. Always back up `.env` and the encrypted database together securely; losing `FERNET_KEY` makes saved keys unrecoverable.

## 4. Telegram workflow

1. `/start` → `اکانت‌ها` → connect via IAM Role or limited IAM Key.
2. `ساخت سرور` → account → AWS Region → Ubuntu version → instance type → disk size → SSH login mode → allowed public SSH IP/CIDR → server name → confirmation.
3. For password mode, the bot sends a **26-character random password** once in the private chat. EC2 User Data contains only a salted SHA-512 password **hash**, not the plaintext password. Cloud-init may require time to apply the SSH settings and a VM may fail to configure; verify before shutting down old systems. No EC2 key pair is created in password mode.
4. For SSH key mode, the bot creates an AWS EC2 Key Pair and sends the private `.pem` **only once**. Save it privately and use `chmod 600 key.pem`, then `ssh -i key.pem ubuntu@SERVER_IP`.
5. `سرورها` → account → region → instance → view status/IP, power actions, CPU metrics or terminate (requires two confirmations).

**SSH example with password:** `ssh ubuntu@PUBLIC_IP` (choose SSH password mode when creating). Default network access should be restricted to your public IP as `/32`; `0.0.0.0/0` is an explicit opt-in and increases exposure.

**Regions:** the selector lists some common AWS Regions *enabled* in the selected account. A geographic location that AWS doesn't operate as a native Region cannot be created through EC2 (for example a general-purpose Finland Region is not part of the current listed choices).

## 5. Costs, safety and limitations

- **Stop ≠ no cost**. Stopped EC2 typically retains chargeable EBS storage, reserved resources and potentially public IPv4-related charges; use AWS Billing to confirm.
- **Terminate deletes instances, not everything**. Root EBS provisioned by this bot has `DeleteOnTermination=True`; user-created attached EBS volumes, Elastic IPs, network resources, key pairs and security groups may remain and incur cost or require manual cleanup.
- EC2 quotas and instance-family availability depend on the specific Region/account; a requested type might not exist or your account may have insufficient quota.
- **No static public IP guaranteed.** The instance receives an auto-assigned public IPv4 where AWS allows; it can change after stop/start. Use an Elastic IP via AWS console if you require static IP, and review the fee.
- Billing totals are **AWS Cost Explorer account estimates**, not realtime charges for the chosen EC2 instance. Cost Explorer requests may have API fees and can require specific billing access.
- Public AWS service access is necessary. The manager is not an AWS-console replacement for organizations, audit policies, networking, account verification or budgets.
- Cloud-init password login is optional and less secure than key-based SSH. The generated password is not stored for recovery. AWS advises against putting any sensitive secret in instance User Data; even a password hash is best avoided in high-security contexts. Prefer SSH keys or SSM Session Manager for sensitive workloads.
- For account security, implement MFA and billing alarms in AWS; the bot itself uses an allowlisted Telegram owner ID and private chat only.
- The current release lists up to 100 EC2 instances per Region and displays the first 35. It does not offer paginated multi-thousand-instance browsing.

## 6. Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt pytest
python -m pytest -q
python -m compileall -q src
```

`src/aws_api.py` isolates boto3 interactions. `src/storage.py` manages encrypted credentials, and `src/bot.py` contains the private Telegram UI. No live AWS credentials are used in tests.

## فارسی — خلاصه نصب

۱. مخزن `Net-spoof/AWS-EC2-Manager-Bot` آماده است؛ آن را روی VPS با `git clone` دریافت کن.

۲. روی سرور مدیریت، Docker نصب کن، `.env.example` را به `.env` کپی کن، مقدار `TELEGRAM_BOT_TOKEN` و `OWNER_TELEGRAM_ID` را وارد کن و یک `FERNET_KEY` تصادفی تولید کن.

۳. با `docker compose up -d --build` ربات را اجرا کن. در پیام خصوصی ربات `/start` بفرست و با IAM Role یا API Key محدود، اکانت AWS را اضافه کن.

۴. از بخش «ساخت سرور» نوع سرور و ریجن را انتخاب کن. حذف سرورها دو مرحله تأیید دارد. برای جلوگیری از هزینه غیرمنتظره حتماً در AWS Budgets هشدار هزینه فعال کن.

**Do not upload `.env`, `.pem` or any AWS credentials to public GitHub.**

## License

No license is granted automatically. Add a license appropriate for your own repository when you are ready.
