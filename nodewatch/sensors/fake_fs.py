"""
sensors.fake_fs
================

Builds the credible fake filesystem the SSH honeypot exposes. Every
identifying value (org name, hostnames, people, customer roster, bait
filenames, secrets) comes from a per-VM FakeWorld instance — so two
installs from the same public deployer source never look alike and an
attacker can't grep the deployer repo for words that appear on their shell.

Two layers:

  Static-ish files : text content built from per-VM FakeWorld values.
                     Multiple template variants picked at install time so
                     even the wording of bait notes differs between VMs.
  Canary files     : DOCX/XLSX generated on-the-fly per session. Each
                     download carries a session-keyed beacon URL that
                     phones home with the attacker's IP when opened.
"""
from __future__ import annotations

import hashlib
import io
import os
import secrets
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Optional

from .fake_world import FakeWorld


DEFAULT_CANARY_BASE = os.environ.get("HP_CANARY_URL", "")


@dataclass
class FileMeta:
    mode: str
    nlink: int
    owner: str
    group: str
    size: int
    mtime: datetime
    is_dir: bool = False
    is_link: bool = False
    link_target: str = ""


# ----------------------------------------------------------------- templates
# Multiple variants per "memorable" file so two VMs don't share recognisable
# phrases. The variant index is chosen per-VM in FakeWorld.

_NOTES_TEMPLATES = [
    # 0 — TODO list, casual
    """\
TODO before {month_words}:
  - rotate db creds (current: {db_pass} — move to Hashicorp Vault!)
  - move admin token out of /opt/app/.env, leaked it in git once
  - set up alerts on the ECR push, {dba_first} missed last rotation
  - decom old prod-01 box, dns still points to 10.10.20.{ip_oct_a}
  - VPN config at /etc/openvpn/client/prod.ovpn renewing in {next_month}

useful urls:
  - admin:    https://internal-admin.{ext_domain}/login
  - grafana:  https://metrics.{int_domain}
  - 1password: https://{org_short}.1password.com (use sso)

ticket #4129 — customer wants the analytics dump
  s3://{org_short}-prod-exports/dump_{today}.csv
  {dba_first} has the SAS key, ping on slack.

DO NOT delete /opt/app/secrets/* even though it looks empty, those are
symlinks into the secrets volume. removing them takes down /api/payments
because the JWT key rotates.
""",
    # 1 — Bullet-style ops note
    """\
ops notes — {today}

* prod migration scheduled for next Tuesday
* {dba_full} will be running the db cutover (he has master pw {db_pass})
* lb is on 10.10.20.{ip_oct_a}, not the dns name in the runbook
* if backups job fails check /var/log/backup.log first then cron
* admin api token is {admin_token} — keep it out of public buckets
* slack incident channel: #incidents-{org_short}
* terraform state: s3://{org_short}-tfstate/prod/main.tfstate

reminders:
- rotate stripe webhook secret (last done {last_rotated})
- audit aws keys with `aws iam list-access-keys`
- check that the kubeconfig service account on bastion still works
- old wifi password is {db_pass2} — change at next office visit
""",
    # 2 — Handover note
    """\
{ops_first} taking over the migration —

things you need to know:
  - the master db on db-prod-01.{int_domain} has the real customer data;
    db-prod-02 is async replica and lags 4-7s
  - {dba_full} owns it. if it breaks call him first (he sleeps with the pager)
  - postgres pass is {db_pass}, don't put this in slack
  - the vault token is {vault_token}, kept in 1pw for now
  - api admin token is {admin_token}, in env file at /opt/app/.env
  - aws keys for the prod profile rotate quarterly, current one
    expires next month
  - grafana lives at metrics.{int_domain}, login is sso
  - terraform state is in s3 under {org_short}-tfstate

next on-call: {ops_full}
""",
    # 3 — Sticky-note style
    """\
- db master pw:  {db_pass}
- second pg:     {db_pass2}
- wifi (old):    {redis_pass}
- vault root:    {vault_token}
- esxi root:     {admin_token}
- router admin:  {admin_token}

dont commit this file again {ops_first}
{dba_full} has the printed copy in his drawer for backup
""",
    # 4 — Project-style
    """\
project rotation Q2

owners:
  database tier:  {dba_full} ({dba_email})
  ops & infra:    {ops_full} ({ops_email})

action items this sprint:
  [ ] move admin api token out of .env and into kubernetes secret
  [ ] rotate all aws access keys (current set provisioned {months_ago} months ago)
  [ ] decommission prod-01 (replaced by autoscaling group last month)
  [ ] postgres master password change ({db_pass} -> hsm-generated)
  [ ] wipe old terraform.tfstate.backup files from s3

resources:
  https://internal-admin.{ext_domain}
  https://metrics.{int_domain}
  https://{org_short}.1password.com
""",
]

_PASSWORDS_TEMPLATES = [
    # 0
    """\
# Personal — do not share

router admin:        {db_pass2}
vmware ESXi (10.10.0.10): root / {admin_token_short}
old wifi key:        {stripe_whsec_short}
vault root token:    {vault_token}

(use 1password from now on!)
""",
    # 1
    """\
my creds (consolidating into 1pw eventually)

aws root (mfa):      {admin_token_short}
office router:       {db_pass2}
home wifi:           {stripe_whsec_short}
psql shared dba:     {db_pass}
nas (Synology):      {redis_pass}
""",
    # 2
    """\
old passwords I haven't moved yet:

  vault root:           {vault_token}
  postgres master:      {db_pass}
  internal admin api:   {admin_token}
  bitwarden master:     {db_pass2}
  pfsense:              {redis_pass}

(everything new goes in 1pw, see runbook)
""",
    # 3
    """\
- bastion sudo:    {db_pass}
- vault token:     {vault_token}
- jenkins admin:   {admin_token}
- ESXi root:       {admin_token_short}
- old wifi:        {stripe_whsec_short}
""",
]

_BASH_HISTORY_ROOT = """\
ls -la
cd /var/log
tail -f auth.log
sudo systemctl restart nginx
docker ps
docker logs payments-api
psql -h db-prod-01.{int_domain} -U postgres -d billing
vim /etc/nginx/sites-available/api.conf
nginx -t
systemctl reload nginx
htop
df -h
free -m
journalctl -u app-payments --since "1 hour ago"
ssh deploy@bastion.{int_domain}
git pull
./scripts/deploy.sh production
exit
ls /opt/backups/
gzip -d db_backup_*.sql.gz
mysql -u root -p < db_backup_2026-05-22.sql
history -c
"""

_BASH_HISTORY_ADMIN = """\
ls
cd ~/scripts
./backup-db.sh
cat .env
vim .env
git status
git diff
git commit -am "rotate api keys"
git push origin main
kubectl get pods -n production
kubectl logs payments-api-7d4c8b6f9-xj2lk -n production
kubectl exec -it payments-api-7d4c8b6f9-xj2lk -n production -- /bin/bash
aws s3 ls s3://{org_short}-prod-backups/
aws s3 cp customers_export.csv s3://{org_short}-prod-backups/exports/
terraform plan
terraform apply -auto-approve
ssh -i ~/.ssh/prod_key.pem ubuntu@10.10.20.{ip_oct_a}
exit
"""

_AUTHORIZED_KEYS_TEMPLATE = """\
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDX8jK5oQR4rPF1cN+mZsLBjF7p8tWqA6V3yU0H deploy@bastion
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINvK4eJp9q8RmF2zXc7tYbHwL5K8nB4vQ {ops_first}@laptop
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9mP8tWqA6V3yU0HX8jK5oQR4rPF1cN+mZsLBjF7p
"""

_SSH_CONFIG = """\
Host bastion
    HostName bastion.{int_domain}
    User deploy
    Port 22
    IdentityFile ~/.ssh/deploy_key

Host db-prod-*
    User dbadmin
    ProxyJump bastion
    IdentityFile ~/.ssh/dbadmin_key

Host vault
    HostName vault.{int_domain}
    User ops
    Port 2222
    IdentityFile ~/.ssh/vault_key

Host backup-server
    HostName 10.10.30.{ip_oct_b}
    User backups
    IdentityFile ~/.ssh/backup_rsa
"""

_KNOWN_HOSTS = """\
bastion.{int_domain} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9j7vK8R+pQ2xN5tWqA6V
db-prod-01.{int_domain} ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI
db-prod-02.{int_domain} ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE
vault.{int_domain} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDX8jK5oQR4rPF1cN+mZsLBjF7p8tWqA6V3y
10.10.20.{ip_oct_a} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINvK4eJp9q8RmF2zXc7tYbH
10.10.30.{ip_oct_b} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJq8RmF2zXc7tYbHwL5K8nB
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
"""

_ID_RSA_PRIV = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxAAAAJg{key_filler_a}
0LH+VtCx{key_filler_b}/lbQsf5W0LH+VtCx/lbQsf5WAAAAC3NzaC1lZDI1NTE5AAAAILf
{key_filler_c}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxAAAAEGRlcGxveUBiYXN0aW9uAQID
-----END OPENSSH PRIVATE KEY-----
"""

_AWS_CREDENTIALS = """\
[default]
aws_access_key_id = {aws_key}
aws_secret_access_key = {aws_secret}
region = us-east-1

[production]
aws_access_key_id = {aws_key2}
aws_secret_access_key = {aws_secret2}
region = us-east-1

[backup]
aws_access_key_id = {aws_key3}
aws_secret_access_key = {aws_secret3}
region = eu-west-1
"""

_AWS_CONFIG = """\
[default]
region = us-east-1
output = json

[profile production]
region = us-east-1
output = json
role_arn = arn:aws:iam::{aws_account_id}:role/ProdAdmin
source_profile = default

[profile backup]
region = eu-west-1
output = json
"""

_KUBE_CONFIG = """\
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCVENDQWUyZ0F3SUJBZ0lJWHQyaitVa3lN
    server: https://k8s-prod.{int_domain}:6443
  name: production
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCVENDQWUyZ0F3SUJBZ0lJTjlhMnBpdEY
    server: https://k8s-staging.{int_domain}:6443
  name: staging
contexts:
- context:
    cluster: production
    namespace: payments
    user: deploy
  name: production
- context:
    cluster: staging
    namespace: default
    user: deploy
  name: staging
current-context: production
users:
- name: deploy
  user:
    token: {k8s_token}
"""

_DOCKER_CONFIG = """\
{{
    "auths": {{
        "https://index.docker.io/v1/": {{
            "auth": "{docker_auth}"
        }},
        "registry.{int_domain}": {{
            "auth": "{registry_auth}"
        }},
        "{aws_account_id}.dkr.ecr.us-east-1.amazonaws.com": {{
            "auth": "{ecr_auth}"
        }}
    }},
    "credsStore": "desktop"
}}
"""

_ENV_APP = """\
# /opt/app/.env
NODE_ENV=production
PORT=3000

# Database
DATABASE_URL=postgres://payments:{db_pass}@db-prod-01.{int_domain}:5432/billing
DB_POOL_MIN=4
DB_POOL_MAX=24
DB_SSL_MODE=require

# Redis
REDIS_URL=redis://:{redis_pass}@redis-prod.{int_domain}:6379/0

# Stripe
STRIPE_SECRET_KEY=sk_live_{stripe_key}
STRIPE_WEBHOOK_SECRET=whsec_{stripe_whsec}

# AWS
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID={aws_key}
AWS_SECRET_ACCESS_KEY={aws_secret}
S3_BUCKET={org_short}-payments-prod

# Email
SMTP_HOST=smtp.{int_domain}
SMTP_PORT=587
SMTP_USER=noreply@{ext_domain}
SMTP_PASS={smtp_pass}

# JWT
JWT_SECRET={jwt_secret}
JWT_ISSUER=auth.{ext_domain}

# Internal admin (do not commit!)
ADMIN_API_URL=https://internal-admin.{ext_domain}/api
ADMIN_API_TOKEN={admin_token}

# Sentry
SENTRY_DSN=https://{sentry_id}@o{aws_account_id}.ingest.sentry.io/{sentry_proj}
"""

_DEPLOY_SH = """\
#!/usr/bin/env bash
# scripts/deploy.sh — push payments service to production
set -euo pipefail

ENV="${{1:-staging}}"
REGION="us-east-1"

export VAULT_ADDR="https://vault.{int_domain}:8200"
export VAULT_TOKEN="{vault_token}"

docker build -t payments-api:latest .
docker tag payments-api:latest {aws_account_id}.dkr.ecr.us-east-1.amazonaws.com/payments-api:latest

aws ecr get-login-password --region "$REGION" \\
  | docker login --username AWS --password-stdin {aws_account_id}.dkr.ecr.us-east-1.amazonaws.com
docker push {aws_account_id}.dkr.ecr.us-east-1.amazonaws.com/payments-api:latest

kubectl --context "$ENV" rollout restart deployment/payments-api -n payments
kubectl --context "$ENV" rollout status   deployment/payments-api -n payments --timeout=5m

curl -s -X POST -H 'Content-Type: application/json' \\
  -d "{{\\"text\\":\\"payments-api deployed to $ENV\\"}}" \\
  https://hooks.slack.com/services/T08{slack_t}/B05{slack_b}/{slack_k}

echo "Done."
"""

_BACKUP_SH = """\
#!/usr/bin/env bash
# scripts/backup-db.sh — nightly db dump
set -euo pipefail

TS=$(date +%Y-%m-%d)
DEST="/var/backups/db_backup_${{TS}}.sql.gz"

PGPASSWORD='{db_pass}' pg_dump \\
  -h db-prod-01.{int_domain} -U postgres -d billing \\
  --no-owner --no-acl \\
  | gzip -9 > "$DEST"

aws s3 cp "$DEST" "s3://{org_short}-prod-backups/db/$(basename $DEST)" --sse AES256
rm -f /var/backups/db_backup_$(date -d '7 days ago' +%Y-%m-%d).sql.gz
"""

_NGINX_CONF = """\
upstream payments_api {{
    server 127.0.0.1:3000 max_fails=3 fail_timeout=10s;
    server 10.10.20.{ip_oct_a}:3000 backup;
}}

server {{
    listen 443 ssl http2;
    server_name api.{ext_domain};

    ssl_certificate     /etc/letsencrypt/live/api.{ext_domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.{ext_domain}/privkey.pem;

    access_log /var/log/nginx/api.access.log combined buffer=64k;
    error_log  /var/log/nginx/api.error.log warn;

    location /healthz {{
        return 200 'ok';
    }}

    location /admin/ {{
        allow 10.10.0.0/16;
        deny  all;
        proxy_pass http://payments_api;
    }}

    location / {{
        proxy_pass http://payments_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}
"""

_MY_CNF = """\
[client]
user=root
password={db_pass}
host=db-prod-01.{int_domain}

[mysqld]
bind-address=0.0.0.0
max_connections=400
innodb_buffer_pool_size=2G
"""

_CROND_BACKUPS = """\
# /etc/cron.d/backups
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=ops@{ext_domain}

15 2 * * * root /home/admin/scripts/backup-db.sh > /var/log/backup.log 2>&1
*/15 * * * * root /opt/app/scripts/ship_logs.sh
30 4 * * * root certbot renew --quiet --post-hook 'systemctl reload nginx'
"""

_AUTH_LOG = """\
{ts1} {host} sshd[{pid1}]: Accepted publickey for deploy from 10.10.5.{ip_oct_a} port 51234 ssh2: ED25519 SHA256:fH7lN9Kx2vQyT8mPzC4nDjBg
{ts2} {host} sshd[{pid2}]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)
{ts3} {host} sudo:  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
{ts4} {host} sshd[{pid3}]: Failed password for root from {scanner_ip} port 44321 ssh2
{ts5} {host} sshd[{pid3}]: Failed password for root from {scanner_ip} port 44321 ssh2
{ts6} {host} sshd[{pid3}]: Failed password for admin from {scanner_ip} port 44322 ssh2
{ts7} {host} sshd[{pid3}]: Connection closed by invalid user oracle 185.220.101.42 port 33421 [preauth]
{ts8} {host} sshd[{pid4}]: Accepted publickey for ops from 10.10.5.{ip_oct_b} port 49221 ssh2: ED25519 SHA256:nB4vQ8RmF2zXc7tYbHwL5K
{ts9} {host} sshd[{pid4}]: pam_unix(sshd:session): session opened for user ops(uid=1002) by (uid=0)
{ts10} {host} sudo:    ops : TTY=pts/1 ; PWD=/home/ops ; USER=root ; COMMAND=/usr/bin/vim /etc/nginx/nginx.conf
"""

_TERRAFORM_TFVARS = """\
# secrets.tfvars — DO NOT COMMIT
aws_access_key      = "{aws_key}"
aws_secret_key      = "{aws_secret}"
db_master_password  = "{db_pass}"
db_replica_password = "{db_pass2}"
vault_token         = "{vault_token}"
slack_webhook       = "https://hooks.slack.com/services/T08{slack_t}/B05{slack_b}/{slack_k}"
github_pat          = "{github_pat}"
datadog_api_key     = "{dd_key}"
datadog_app_key     = "{dd_app_key}"
"""

_RUNBOOK = """\
# {org_short} — ops runbook

## Daily

  - check `#alerts` slack
  - https://metrics.{int_domain}/d/payments — payments dashboard
  - tail nginx errors: `ssh bastion -- 'tail -F /var/log/nginx/api.error.log'`

## Common operations

### Restart payments-api
    kubectl --context production rollout restart deployment/payments-api -n payments

### Restore from backup
    aws s3 cp s3://{org_short}-prod-backups/db/db_backup_YYYY-MM-DD.sql.gz /tmp/
    gunzip -d /tmp/db_backup_*.sql.gz
    psql -h db-prod-01.{int_domain} -U postgres billing < /tmp/db_backup_*.sql

### Rotate API key
    1. mint new key in vault: `vault write secret/payments/api-key`
    2. update k8s secret: `kubectl create secret generic ...`
    3. roll deployment: `kubectl rollout restart deployment/payments-api`

### Get to prod db
    ssh -L 5432:db-prod-01.{int_domain}:5432 bastion
    psql -h 127.0.0.1 -U postgres -d billing

## Contacts

  - on-call: @ops-oncall (pagerduty)
  - db owner: {dba_full} ({dba_email})
  - sec: secops@{ext_domain}
"""

_VPN_OVPN = """\
client
dev tun
proto udp
remote vpn.{ext_domain} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
key-direction 1
verb 3

<ca>
-----BEGIN CERTIFICATE-----
{cert_filler}
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
{cert_filler2}
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
{cert_filler3}
-----END PRIVATE KEY-----
</key>
"""


# ----------------------------------------------------------------------- FS
class FakeFS:
    """Per-VM fake filesystem. All identifying content comes from FakeWorld
    so two installs from the same deployer never share recognisable fingerprints."""

    def __init__(self, world: FakeWorld, hostname: str,
                 canary_base: str = DEFAULT_CANARY_BASE) -> None:
        self.world = world
        self.agent = world.agent_name
        self.hostname = hostname
        self.canary_base = canary_base.rstrip("/")

        # Render the per-VM values once for template formatting
        self.v = dict(world.values)
        self.v["host"] = hostname
        self.v["agent"] = self.agent
        self.v["canary_base"] = self.canary_base
        now = datetime.now(timezone.utc)
        self.v["today"] = now.strftime("%Y-%m-%d")
        self.v["month_words"] = now.strftime("%B").lower()
        self.v["next_month"] = (now + timedelta(days=30)).strftime("%b").lower()
        self.v["last_rotated"] = (now - timedelta(days=42)).strftime("%Y-%m-%d")
        self.v["months_ago"] = 3
        # Truncated secrets for the password-list templates
        self.v["admin_token_short"]  = str(self.v["admin_token"])[:14]
        self.v["stripe_whsec_short"] = str(self.v["stripe_whsec"])[:16]
        # Log line timestamps
        for i, (h, m) in enumerate([(8, 0), (8, 0), (7, 58), (6, 12),
                                     (6, 12), (6, 11), (4, 33), (2, 41),
                                     (2, 41), (0, 14)], start=1):
            self.v[f"ts{i}"] = (now - timedelta(hours=h, minutes=m)).strftime("%b %d %H:%M:%S")

        # Stable RNG for any non-content randomness (sizes, timestamps)
        seed = hashlib.sha256(f"{self.agent}|fs".encode()).digest()
        import random as _r
        self._rng = _r.Random(int.from_bytes(seed[:8], "big"))

        self._files: dict[str, bytes] = {}
        self._meta:  dict[str, FileMeta] = {}
        self._canary_paths: dict[str, tuple] = {}
        self._build()

    # ------------------- public api -------------------
    def exists(self, path: str) -> bool:
        return self._norm(path) in self._meta

    def is_dir(self, path: str) -> bool:
        p = self._norm(path)
        return p in self._meta and self._meta[p].is_dir

    def is_file(self, path: str) -> bool:
        p = self._norm(path)
        return p in self._meta and not self._meta[p].is_dir

    def is_canary(self, path: str) -> bool:
        return self._norm(path) in self._canary_paths

    def read(self, path: str, *, session_id: str = "noses",
             max_bytes: Optional[int] = None) -> bytes:
        path = self._norm(path)
        if path in self._canary_paths:
            _mime, builder = self._canary_paths[path]
            data = builder(session_id)
        elif path in self._files:
            data = self._files[path]
        else:
            raise FileNotFoundError(path)
        if max_bytes is not None:
            data = data[:max_bytes]
        return data

    def meta(self, path: str) -> FileMeta:
        p = self._norm(path)
        if p not in self._meta:
            raise FileNotFoundError(path)
        return self._meta[p]

    def list_dir(self, path: str) -> list[tuple[str, FileMeta]]:
        p = self._norm(path)
        if p not in self._meta or not self._meta[p].is_dir:
            raise NotADirectoryError(path)
        prefix = p.rstrip("/") + "/" if p != "/" else "/"
        out: list[tuple[str, FileMeta]] = []
        seen: set[str] = set()
        for k, m in self._meta.items():
            if not k.startswith(prefix) or k == p:
                continue
            rest = k[len(prefix):]
            if not rest:
                continue
            name = rest.split("/", 1)[0]
            if name in seen:
                continue
            seen.add(name)
            child = prefix + name
            cm = self._meta.get(child, m)
            out.append((name, cm))
        out.sort(key=lambda kv: kv[0])
        return out

    def all_paths(self) -> list[str]:
        return sorted(self._meta.keys())

    @staticmethod
    def _norm(path: str) -> str:
        if not path:
            return "/"
        p = PurePosixPath(path)
        resolved: list[str] = []
        for part in p.parts:
            if part == "..":
                if len(resolved) > 1:
                    resolved.pop()
            elif part in (".", ""):
                if not resolved:
                    resolved.append("/")
            else:
                resolved.append(part)
        if not resolved or resolved == ["/"]:
            return "/"
        return "/" + "/".join(p for p in resolved if p != "/")

    # ------------------- internal: build tree -------------------
    def _fmt(self, tpl: str) -> bytes:
        try:
            return tpl.format(**self.v).encode("utf-8")
        except KeyError as e:
            return f"[template-error: missing {e}]\n".encode()

    def _customers_csv(self) -> bytes:
        rows = ["customer_id,email,name,company,plan,mrr_usd,signup_date,country"]
        for c in self.v.get("customers", []):
            rows.append(f'{c["id"]},{c["email"]},{c["name"]},'
                         f'"{c["company"]}",{c["plan"]},{c["mrr_usd"]},'
                         f'{c["signup_date"]},{c["country"]}')
        return ("\n".join(rows) + "\n").encode()

    def _build(self) -> None:
        v = self.v

        def add(path, content, mode="-rw-r--r--", owner="root", group="root",
                mtime_offset_h=0, nlink=1):
            if isinstance(content, str):
                content = self._fmt(content)
            self._files[path] = content
            self._meta[path] = FileMeta(
                mode=mode, nlink=nlink, owner=owner, group=group,
                size=len(content),
                mtime=datetime.now(timezone.utc) - timedelta(hours=mtime_offset_h),
            )

        def add_dir(path, mode="drwxr-xr-x", owner="root", group="root",
                    mtime_offset_h=0, nlink=2):
            self._meta[path] = FileMeta(
                mode=mode, nlink=nlink, owner=owner, group=group, size=4096,
                mtime=datetime.now(timezone.utc) - timedelta(hours=mtime_offset_h),
                is_dir=True,
            )

        # /etc — system files (mostly standard, content references int_domain)
        add("/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "sync:x:4:65534:sync:/bin:/bin/sync\n"
            "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
            "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n"
            "_apt:x:105:65534::/nonexistent:/usr/sbin/nologin\n"
            "messagebus:x:106:112::/nonexistent:/usr/sbin/nologin\n"
            "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
            "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
            "admin:x:1001:1001:Admin User,,,:/home/admin:/bin/bash\n"
            "deploy:x:1002:1002:Deploy Bot,,,:/home/deploy:/bin/bash\n"
            "ops:x:1003:1003:Ops Team,,,:/home/ops:/bin/bash\n"
            "postgres:x:113:118:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"
            "mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false\n"
            "redis:x:115:120:Redis,,,:/var/lib/redis:/usr/sbin/nologin\n")
        add("/etc/shadow", "", mode="-rw-------")
        add("/etc/group",
            "root:x:0:\nsudo:x:27:admin,deploy,ops\n"
            "ubuntu:x:1000:\nadmin:x:1001:\ndeploy:x:1002:\nops:x:1003:\n"
            "docker:x:998:admin,deploy\n")
        add("/etc/hostname", self.hostname + "\n")
        add("/etc/hosts",
            "127.0.0.1 localhost\n"
            f"127.0.1.1 {self.hostname}\n"
            f"10.10.20.{v['ip_oct_a']} db-prod-01.{v['int_domain']} db-prod-01\n"
            f"10.10.20.{v['ip_oct_b']} db-prod-02.{v['int_domain']} db-prod-02\n"
            f"10.10.5.10 bastion.{v['int_domain']} bastion\n"
            f"10.10.30.42 vault.{v['int_domain']} vault\n")
        add("/etc/os-release",
            'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
            'NAME="Ubuntu"\nVERSION_ID="22.04"\n'
            'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
            'VERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\n')
        add("/etc/resolv.conf",
            f"search {v['int_domain']}\n"
            "nameserver 10.10.0.2\nnameserver 10.10.0.3\nnameserver 1.1.1.1\n")
        add("/etc/crontab", "")
        add("/etc/cron.d/backups", _CROND_BACKUPS)
        add("/etc/nginx/sites-available/api.conf", _NGINX_CONF)
        add("/etc/nginx/sites-enabled/api.conf", _NGINX_CONF, mode="lrwxrwxrwx")
        add("/etc/mysql/my.cnf", _MY_CNF, mode="-rw-r-----", owner="mysql", group="mysql")
        add("/etc/openvpn/client/prod.ovpn", _VPN_OVPN, mode="-rw-------")

        # /root — picks notes/passwords variants per-VM (template id from FakeWorld)
        notes_template = _NOTES_TEMPLATES[v["notes_template_id"] % len(_NOTES_TEMPLATES)]
        passwords_template = _PASSWORDS_TEMPLATES[v["passwords_template_id"] % len(_PASSWORDS_TEMPLATES)]

        add("/root/.bash_history", _BASH_HISTORY_ROOT, mode="-rw-------")
        add("/root/.profile",
            "# ~/.profile\nif [ -n \"$BASH_VERSION\" ]; then\n"
            "    if [ -f \"$HOME/.bashrc\" ]; then . \"$HOME/.bashrc\"; fi\nfi\n"
            "PATH=\"$HOME/bin:$PATH\"\n")
        add("/root/.bashrc",
            "# ~/.bashrc — root\n"
            "export PS1='\\u@\\h:\\w# '\nexport HISTSIZE=10000\nexport HISTCONTROL=ignoredups\n"
            "alias ll='ls -la'\nalias deploy='~/scripts/deploy.sh'\n")
        add("/root/.ssh/authorized_keys", _AUTHORIZED_KEYS_TEMPLATE, mode="-rw-------")
        add("/root/.ssh/known_hosts", _KNOWN_HOSTS, mode="-rw-r--r--")
        add("/root/.ssh/config", _SSH_CONFIG, mode="-rw-------")
        add("/root/.ssh/id_rsa", _ID_RSA_PRIV, mode="-rw-------")
        add("/root/.ssh/id_rsa.pub",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDX8jK5oQR4rPF1cN+mZsLBjF7p root@" + self.hostname + "\n")

        # Bait files with randomized names from FakeWorld
        add(f"/root/{v['notes_filename']}", notes_template, mtime_offset_h=2)
        add(f"/root/{v['passwords_filename']}", passwords_template,
            mode="-rw-------", mtime_offset_h=120)

        # /home/admin
        add("/home/admin/.bash_history", _BASH_HISTORY_ADMIN, mode="-rw-------", owner="admin", group="admin")
        add("/home/admin/.profile", "# ~/.profile\nPATH=\"$HOME/bin:$PATH\"\n", owner="admin", group="admin")
        add("/home/admin/.bashrc",
            "alias ll='ls -la'\nalias k='kubectl'\nalias tf='terraform'\n",
            owner="admin", group="admin")
        add("/home/admin/scripts/deploy.sh", _DEPLOY_SH, mode="-rwxr-xr-x", owner="admin", group="admin")
        add("/home/admin/scripts/backup-db.sh", _BACKUP_SH, mode="-rwxr-xr-x", owner="admin", group="admin")
        add("/home/admin/.aws/credentials", _AWS_CREDENTIALS, mode="-rw-------", owner="admin", group="admin")
        add("/home/admin/.aws/config", _AWS_CONFIG, owner="admin", group="admin")
        add("/home/admin/.kube/config", _KUBE_CONFIG, mode="-rw-------", owner="admin", group="admin")
        add("/home/admin/.docker/config.json", _DOCKER_CONFIG, mode="-rw-------", owner="admin", group="admin")
        add("/home/admin/.ssh/authorized_keys", _AUTHORIZED_KEYS_TEMPLATE, mode="-rw-------", owner="admin", group="admin")
        add("/home/admin/.ssh/config", _SSH_CONFIG, mode="-rw-------", owner="admin", group="admin")
        add("/home/admin/.ssh/known_hosts", _KNOWN_HOSTS, owner="admin", group="admin")
        add("/home/admin/.ssh/id_ed25519", _ID_RSA_PRIV.replace("ssh-ed25519", "ed25519"),
            mode="-rw-------", owner="admin", group="admin")
        add("/home/admin/terraform/main.tf",
            "# infra/main.tf\nterraform {{\n  backend \"s3\" {{\n"
            "    bucket = \"{org_short}-tfstate\"\n    key = \"prod/main.tfstate\"\n"
            "    region = \"us-east-1\"\n    encrypt = true\n  }}\n}}\n", owner="admin", group="admin")
        add("/home/admin/terraform/secrets.tfvars", _TERRAFORM_TFVARS,
            mode="-rw-------", owner="admin", group="admin")

        # /home/deploy, /home/ops, /home/ubuntu
        add("/home/deploy/.bash_history",
            "ssh bastion\ngit pull\nkubectl apply -f k8s/\n"
            "kubectl logs -f payments-api-7d4c8b6f9-xj2lk\n"
            "docker build -t payments .\nexit\n",
            mode="-rw-------", owner="deploy", group="deploy")
        add("/home/deploy/.profile", "PATH=\"$HOME/bin:$PATH\"\n", owner="deploy", group="deploy")
        add("/home/ops/runbook.md", _RUNBOOK, owner="ops", group="ops")
        add("/home/ops/.bash_history",
            "tail -F /var/log/nginx/api.error.log\n"
            "psql -h db-prod-01 -U postgres billing\n"
            "vault read secret/payments/api-key\n"
            "kubectl get pods -n payments\nexit\n",
            mode="-rw-------", owner="ops", group="ops")
        add("/home/ubuntu/.bash_history",
            "ls\npwd\nwhoami\nsudo su -\nexit\n",
            mode="-rw-------", owner="ubuntu", group="ubuntu")

        # /opt/app
        add("/opt/app/.env", _ENV_APP, mode="-rw-------", owner="deploy", group="deploy")
        add("/opt/app/config.yaml",
            "server:\n  port: 3000\n  workers: 8\n\n"
            f"database:\n  host: db-prod-01.{v['int_domain']}\n"
            "  port: 5432\n  database: billing\n  pool_size: 24\n\n"
            "logging:\n  level: info\n  format: json\n  destination: stdout\n",
            owner="deploy", group="deploy")
        add("/opt/app/package.json",
            '{{\n  "name": "payments-api",\n  "version": "2.14.3",\n'
            '  "dependencies": {{\n'
            '    "express": "^4.18.2",\n    "pg": "^8.11.0",\n'
            '    "stripe": "^14.5.0",\n    "@aws-sdk/client-s3": "^3.450.0"\n  }}\n}}\n',
            owner="deploy", group="deploy")

        # /var/backups — including a randomly-named DBA handover note
        gz_header = b"\x1f\x8b\x08\x00"
        backup_body = gz_header + bytes(self._rng.randint(0, 255) for _ in range(2048))
        self._files[f"/var/backups/db_backup_{v['today']}.sql.gz"] = backup_body
        self._meta[f"/var/backups/db_backup_{v['today']}.sql.gz"] = FileMeta(
            mode="-rw-r--r--", nlink=1, owner="root", group="root",
            size=len(backup_body),
            mtime=datetime.now(timezone.utc) - timedelta(hours=14),
        )
        self._files["/var/backups/customers_export.csv"] = self._customers_csv()
        self._meta["/var/backups/customers_export.csv"] = FileMeta(
            mode="-rw-r--r--", nlink=1, owner="root", group="root",
            size=len(self._files["/var/backups/customers_export.csv"]),
            mtime=datetime.now(timezone.utc) - timedelta(hours=72),
        )
        add(f"/var/backups/notes-from-{v['dba_first'].lower()}.txt",
            "Reminder: db backups will fail if you regen the SSL cert without "
            "updating /etc/mysql/conf.d/ssl.cnf. Hit me on slack if you see "
            "the cron complaining.\n\nAlso the staging DB password is the "
            "same as prod for now. I know. It's on my list.\n  - " +
            v["dba_first"] + "\n",
            mtime_offset_h=240)

        # /var/log
        add("/var/log/auth.log", _AUTH_LOG, mode="-rw-r-----", owner="syslog", group="adm")
        first_customer_id = (v["customers"][0]["id"] if v.get("customers") else 8472)
        add("/var/log/nginx/api.access.log",
            f"10.10.5.42 - - [25/May/2026:14:32:01 +0000] \"GET /api/payments/4129 HTTP/1.1\" 200 412\n"
            f"10.10.5.42 - - [25/May/2026:14:32:01 +0000] \"GET /api/customer/{first_customer_id} HTTP/1.1\" 200 821\n"
            f"{v['scanner_ip']} - - [25/May/2026:14:32:14 +0000] \"GET /admin/ HTTP/1.1\" 403 162\n"
            f"10.10.5.42 - - [25/May/2026:14:32:18 +0000] \"POST /api/payments/charge HTTP/1.1\" 200 47\n",
            owner="www-data", group="adm")

        # /proc
        add("/proc/cpuinfo",
            "processor\t: 0\nvendor_id\t: GenuineIntel\n"
            "model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\n"
            "cpu MHz\t\t: 2499.998\ncache size\t: 36608 KB\n\n"
            "processor\t: 1\nvendor_id\t: GenuineIntel\n"
            "model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\n"
            "cpu MHz\t\t: 2499.998\ncache size\t: 36608 KB\n")
        add("/proc/meminfo",
            "MemTotal:        4030788 kB\nMemFree:          312540 kB\n"
            "MemAvailable:    1820432 kB\nBuffers:          120384 kB\n"
            "Cached:          1342016 kB\n")
        add("/proc/version",
            "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-027) "
            "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #101-Ubuntu SMP\n")

        # Canary docs — randomized filenames from FakeWorld
        self._canary_paths = {
            f"/root/{v['canary_doc_name']}.docx": (
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                self._build_canary_docx),
            f"/root/{v['canary_xls_name']}.xlsx": (
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                self._build_canary_xlsx),
            f"/var/backups/{v['canary_doc_backup_name']}.docx": (
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                self._build_canary_docx),
        }
        for p in self._canary_paths:
            self._meta[p] = FileMeta(
                mode="-rw-------", nlink=1, owner="root", group="root",
                size=18000 + self._rng.randint(0, 4000),
                mtime=datetime.now(timezone.utc) - timedelta(hours=self._rng.randint(2, 96)),
            )

        # Auto-create parent directories
        for path in list(self._files.keys()) + list(self._canary_paths.keys()):
            parts = PurePosixPath(path).parts
            for i in range(1, len(parts)):
                d = "/" + "/".join(parts[1:i])
                if d and d not in self._meta:
                    add_dir(d)

        # Adjust dir owners/modes for realism
        for d, owner, group in [
            ("/home", "root", "root"),
            ("/home/admin", "admin", "admin"),
            ("/home/admin/.ssh", "admin", "admin"),
            ("/home/admin/.aws", "admin", "admin"),
            ("/home/admin/.kube", "admin", "admin"),
            ("/home/admin/.docker", "admin", "admin"),
            ("/home/admin/scripts", "admin", "admin"),
            ("/home/admin/terraform", "admin", "admin"),
            ("/home/deploy", "deploy", "deploy"),
            ("/home/ops", "ops", "ops"),
            ("/home/ubuntu", "ubuntu", "ubuntu"),
            ("/root", "root", "root"),
            ("/root/.ssh", "root", "root"),
        ]:
            if d in self._meta:
                m = self._meta[d]
                m.owner = owner
                m.group = group
                if d.endswith(".ssh"):
                    m.mode = "drwx------"

    # ------------------- canary doc builders -------------------
    def _build_canary_docx(self, session_id: str) -> bytes:
        token = secrets.token_urlsafe(12)
        beacon = (f"{self.canary_base}/{self.agent}/{session_id}/{token}.png"
                   if self.canary_base else f"about:blank#{token}")
        v = self.v
        content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''
        rels_root = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>'''
        rels_doc = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId100" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{beacon}" TargetMode="External"/>
</Relationships>'''
        document_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
            xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
            xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
            xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
<w:body>
<w:p><w:r><w:t xml:space="preserve">CONFIDENTIAL — {v['org_short']} infrastructure secrets export</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">Source: vault.{v['int_domain']}</w:t></w:r></w:p>
<w:p/>
<w:p><w:r><w:t xml:space="preserve">Database master:</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">  host: db-prod-01.{v['int_domain']}</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">  user: postgres</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">  pass: {v['db_pass']}</w:t></w:r></w:p>
<w:p/>
<w:p><w:r><w:t xml:space="preserve">AWS production keys:</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">  access_key: {v['aws_key2']}</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">  secret_key: {v['aws_secret2']}</w:t></w:r></w:p>
<w:p/>
<w:p><w:r><w:drawing>
<wp:inline distT="0" distB="0" distL="0" distR="0">
<wp:extent cx="2381250" cy="1190625"/>
<wp:docPr id="1" name="Picture 1"/>
<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
<pic:pic>
<pic:nvPicPr><pic:cNvPr id="1" name="logo.png"/><pic:cNvPicPr/></pic:nvPicPr>
<pic:blipFill><a:blip r:embed="" r:link="rId100"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>
<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="2381250" cy="1190625"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>
</pic:pic>
</a:graphicData>
</a:graphic>
</wp:inline>
</w:drawing></w:r></w:p>
</w:body>
</w:document>'''
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", content_types)
            z.writestr("_rels/.rels", rels_root)
            z.writestr("word/_rels/document.xml.rels", rels_doc)
            z.writestr("word/document.xml", document_xml)
        return buf.getvalue()

    def _build_canary_xlsx(self, session_id: str) -> bytes:
        token = secrets.token_urlsafe(12)
        beacon = (f"{self.canary_base}/{self.agent}/{session_id}/{token}.png"
                   if self.canary_base else f"about:blank#{token}")
        content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/drawings/drawing1.xml" ContentType="application/vnd.openxmlformats-officedocument.drawing+xml"/>
</Types>'''
        rels_root = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>'''
        wb_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>'''
        sheet_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing" Target="../drawings/drawing1.xml"/>
</Relationships>'''
        drawing_rels = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{beacon}" TargetMode="External"/>
</Relationships>'''
        workbook = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Customers" sheetId="1" r:id="rId1"/></sheets>
</workbook>'''
        rows_xml = []
        rows_xml.append(
            '<row r="1">'
            '<c r="A1" t="inlineStr"><is><t>customer_id</t></is></c>'
            '<c r="B1" t="inlineStr"><is><t>email</t></is></c>'
            '<c r="C1" t="inlineStr"><is><t>company</t></is></c>'
            '<c r="D1" t="inlineStr"><is><t>plan</t></is></c>'
            '<c r="E1" t="inlineStr"><is><t>mrr_usd</t></is></c>'
            '</row>')
        for i, c in enumerate(self.v.get("customers", []), start=2):
            email = c["email"].replace("&", "&amp;")
            company = c["company"].replace("&", "&amp;")
            rows_xml.append(
                f'<row r="{i}">'
                f'<c r="A{i}"><v>{c["id"]}</v></c>'
                f'<c r="B{i}" t="inlineStr"><is><t>{email}</t></is></c>'
                f'<c r="C{i}" t="inlineStr"><is><t>{company}</t></is></c>'
                f'<c r="D{i}" t="inlineStr"><is><t>{c["plan"]}</t></is></c>'
                f'<c r="E{i}"><v>{c["mrr_usd"]}</v></c>'
                f'</row>')
        sheet1 = (f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
           xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheetData>
{"".join(rows_xml)}
</sheetData>
<drawing r:id="rId1"/>
</worksheet>''')
        drawing1 = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing"
          xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<xdr:twoCellAnchor>
<xdr:from><xdr:col>6</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>1</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from>
<xdr:to><xdr:col>10</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>10</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:to>
<xdr:pic>
<xdr:nvPicPr><xdr:cNvPr id="2" name="logo.png"/><xdr:cNvPicPr/></xdr:nvPicPr>
<xdr:blipFill><a:blip r:link="rId1"/><a:stretch><a:fillRect/></a:stretch></xdr:blipFill>
<xdr:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="2381250" cy="1190625"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></xdr:spPr>
</xdr:pic>
<xdr:clientData/>
</xdr:twoCellAnchor>
</xdr:wsDr>'''
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", content_types)
            z.writestr("_rels/.rels", rels_root)
            z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
            z.writestr("xl/worksheets/_rels/sheet1.xml.rels", sheet_rels)
            z.writestr("xl/drawings/_rels/drawing1.xml.rels", drawing_rels)
            z.writestr("xl/workbook.xml", workbook)
            z.writestr("xl/worksheets/sheet1.xml", sheet1)
            z.writestr("xl/drawings/drawing1.xml", drawing1)
        return buf.getvalue()
