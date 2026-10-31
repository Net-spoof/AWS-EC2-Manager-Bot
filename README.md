# ☁️ AWS EC2 Manager Bot

**Private, Persian-language Telegram control plane for multiple AWS accounts.**

A pragmatic owner-only implementation for provisioning multi-OS EC2 instances and operating existing EC2 servers. Supports multiple IAM key connections encrypted on disk, or AWS cross-account `AssumeRole` connections without transferring account API secrets through Telegram.

> ⚠️ This project is provided as a deployable **initial release**, not a production-certified cloud control plane. It has not been tested against a live AWS account from this environment. AWS resources incur real charges. Start with an account/budget dedicated to testing.

## Features

| Feature | Included |
| --- | --- |
| Persian Telegram menus, owner-only private chat access | ✅ |
| Add/remove/test multiple AWS IAM access key accounts | ✅ |
| Add/remove/test multiple AssumeRole accounts | ✅ |
| Dynamic AWS Region list (enabled/opt-in), Persian flags and pagination | ✅ (v1.3) |
| On-Demand EC2 hourly and monthly pricing preview + creation receipt | ✅ (v1.3) |
| Vertically stacked CPU/RAM instance-type buttons | ✅ (v1.3) |
| EC2 multi-OS wizard: Ubuntu, Debian, Amazon Linux, Windows Server, RHEL, SLES, Rocky and custom AMIs | ✅ (v1.4) |
| t3 and t3a x86 instance choices, gp3 encrypted root disk | ✅ |
| SSH access via auto-generated .pem key or random password | ✅ |
| Adjustable SSH firewall CIDR | ✅ |
| List existing EC2 instances in selected account & Region | ✅ |
| In-bot EC2 Security Group: ping on/off, TCP/UDP ingress, list/remove rules | ✅ (v1.1) |
| Rotate an existing EC2 root password over verified SSH | ✅ (v1.1; existing root login required) |
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
2. `ساخت سرور` → account → AWS Region → OS family → OS version → instance type → disk size → SSH login mode → allowed public SSH IP/CIDR → server name → confirmation.
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


## v1.1 — Firewall & root password rotation

Update an already installed bot without deleting its `.env` or Docker data volume:

```bash
cd ~/AWS-EC2-Manager-Bot   # replace with your actual repository path
git pull --ff-only
sudo docker compose up -d --build
sudo docker compose logs --tail=50
```

**Telegram:** `/start` → `سرورها` → AWS account → Region → EC2 instance.

- **🛡 Firewall & Ping:** choose one security group attached to that instance, view inbound rules, toggle ICMP Echo Request (`8/0` from `0.0.0.0/0`), or add TCP/UDP ports/ranges restricted to an IPv4 CIDR. Remove a specific inbound rule using its unique AWS rule ID and an additional confirmation. Deleting rules that cover SSH port 22 (or allow all protocols) is intentionally blocked to prevent lockout. This is an **AWS Security Group** operation, not an Ubuntu UFW operation. Firewall changes can affect *all* instances sharing the group. The UI displays only the first 24 rules and exposes removal controls for the first 20. It does not manage outbound/IPv6 rules or edit existing CIDRs. Creating a port rule does not start a service inside the VM.
- **🔐 Change root password:** works on an **existing running EC2 instance** only if root password SSH login on port 22 is already enabled, bot host can reach the EC2 public IPv4, and the existing root password is known. First the bot retrieves the SSH host key fingerprint. **Independently verify the fingerprint on the EC2 instance before confirming** (`sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`; match the algorithm shown in the bot). The bot then asks for the current root password and creates a new 30-character random password, sets it via `chpasswd` over an encrypted verified SSH session, and displays the new password once. The existing password is held only transiently in memory; new and old passwords are **not stored in SQLite or activity logs**. Telegram bot chats are *not* end-to-end encrypted; avoid this feature for high-security production servers. Prefer SSH keys for management where possible. Note that a changed root password does not automatically change the `ubuntu` user's password.

**IAM policy:** Using the project's restricted policy requires new actions `ec2:DescribeSecurityGroupRules` and `ec2:RevokeSecurityGroupIngress` for firewall management. Re-attach the updated [IAM policy](deploy/iam-ec2-manager-policy.json) or update the existing managed policy. Root SSH password rotation uses an outbound SSH session from the bot host and does not itself require additional AWS IAM rights beyond `ec2:DescribeInstances`.

**Security:** Never commit `.env`, IAM secrets, or SSH passwords; if a private root password has appeared in a screenshot or public chat, rotate it. Limit `tcp/22` to trusted source IPs rather than `0.0.0.0/0`. Use the AWS console for emergency recovery if your SSH login stops working.

### v1.2 — Persian regions in Telegram

The EC2 creation and instance-list Region pickers show the country flag and Persian country/geography name, followed by the exact AWS Region ID (e.g. `🇩🇪 آلمان — فرانکفورت (eu-central-1)`). The picker has eight one-column choices per page for readability on mobile. AWS API requests and stored Regions still use original Region IDs. Region options remain limited to the locations enabled for each AWS account. No IAM changes or data migration are needed.

### v1.3 — AWS Region discovery, EC2 price estimate, mobile buttons

- Reads the real AWS account's opt-in status using `ec2:DescribeRegions(AllRegions=True)`, showing enabled Regions for server creation and disabled (opt-in) Regions separately. An opt-in Region must be enabled through **AWS Console → Account → AWS Regions**; this bot does not grant itself permissions to enable AWS Regions.
- The instance type (CPU/RAM) choices now appear **one per row** to fit Telegram on mobile.
- Before confirming EC2 creation and after successful creation, attempts a **live AWS Price List GetProducts** quote for Linux On-Demand **EC2 compute**, **gp3 EBS provisioned storage** and the published **$0.005/hr public IPv4** fee. Monthly projection assumes **730 hours**. Other EBS provisions, network traffic, CPU credit surplus for burstable T3, taxes, tier benefits, promotions, Savings Plans, discounts and other services are **not included**. If EC2 pricing is unavailable, the bot states it does not know the price instead of guessing; if gp3 pricing fails, it displays an explicitly incomplete subtotal. AWS Cost Explorer/account billing remains authoritative for charges.
- For IAM users using the project's managed example policy, update the AWS IAM policy to add `pricing:GetProducts` with Resource `*`. This is only for price lookup; the bot still creates servers when pricing cannot be read.
- Refresh the Docker container after `git pull` using `docker compose up -d --build`; **do not run `down -v`**, which deletes the encrypted account database.


### v1.4 — Multi-OS EC2 creation and advanced AMI support

**Telegram creation wizard:** account → enabled AWS Region → OS family → version →
CPU/RAM → disk → remote login → allowed source CIDR → name → price preview → confirm.
Available families include Ubuntu 22.04/24.04/26.04, Debian 12/13, Amazon Linux
2/2023, Windows Server 2019/2022/2025, RHEL 8/9/10, SUSE SLES 15, Rocky Linux
8/9, and an **AMI ID** option for any other accessible OS (e.g. AlmaLinux,
Fedora or AWS Marketplace images). The menu cannot list every Marketplace image
by name; manual AMI ID is the escape hatch. Version availability varies by Region.

- Ubuntu: existing optional cloud-init SSH password or SSH key. Login: `ubuntu`.
- Debian: SSH key, default login `admin`.
- Amazon Linux/RHEL/SUSE: SSH key, default login typically `ec2-user`.
- Rocky: SSH key, default login generally `rocky` (verify the image documentation).
- Windows Server: **RDP port 3389** not SSH 22. RSA key pair is created and
  delivered privately once. Use **AWS EC2 → Instances → Connect → RDP client → Get password**
  and upload the `.pem` key to decrypt the built-in `Administrator` password.
  AWS password initialization can take up to 15 minutes. The bot never invents
  a Windows password or exposes plaintext credentials in EC2 User Data.
  The wizard requires at least `t3.medium`/4 GiB RAM and offers disks >=40 GiB.
- Custom AMIs: must be available in the selected Region, x86_64 and EBS-backed.
  The bot inspects the AMI platform and minimum root-disk size, and uses SSH
  key/RDP appropriately. For unknown Linux vendors the default username must
  be checked against the publisher's documentation. AWS Marketplace images
  may require a subscription and can incur additional licensing charges.
- Pricing: live AWS Pricing `GetProducts` tries to use Windows/RHEL/SUSE
  operating-system rates rather than always assuming Linux. If the catalog
  does not return a trustworthy price, the bot clearly states pricing is
  unavailable. For custom/unknown AMIs, pricing is never guessed.
- Add SSM public-parameter read rights for Amazon Linux and Windows Server
  (the example `deploy/iam-ec2-manager-policy.json` includes them).

**Security:** restrict SSH 22 / RDP 3389 to a trusted source IP. AWS Security
Groups are managed by the account; there is no inbound port on the bot VPS.
The bot's firewall rule-removal protection includes both management ports.
**Testing:** unit tests use stubbed AWS sessions, not a billable EC2 account.

### v1.5 — Enable opt-in Regions from Telegram

The inactive Region picker now provides an owner-only **Enable Region** action with two confirmation screens. It uses the **AWS Account Management** API `GetRegionOptStatus` and `EnableRegion` against the credentials of the selected AWS account; **no root credentials** and no manual account ID are required. The operation does not create any EC2 instances. The bot explicitly displays `DISABLED`, `ENABLING`, `ENABLED` or `DISABLING` and has a **Refresh status** button; when enabled, select the Region again from the refreshed Region menu. The request can take minutes to hours. No automatic disabling of Regions is implemented.

If your IAM user/role uses the example policy, **update the existing IAM policy** from `deploy/iam-ec2-manager-policy.json`, or attach the following inline policy to the same IAM principal:

```json
{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Action":["account:GetRegionOptStatus","account:EnableRegion"],
    "Resource":"*"
  }]
}
```

Some AWS Organizations may restrict Region opt-in via service control policies or account restrictions; ordinary IAM permissions cannot override such restrictions. For linked AWS accounts, the bot's IAM identity in **each selected account** needs the permissions. Never use `AdministratorAccess` just for this feature. After `git pull --ff-only`, run `docker compose up -d --build` on the bot host. Avoid `down -v` (database deletion).
