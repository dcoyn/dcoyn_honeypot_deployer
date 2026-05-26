"""
sensors.fake_world
==================

Per-VM random "universe" for the SSH honeypot's fake filesystem. Picks an
org name, hostnames, person names, customer roster, bait filenames, AWS
account IDs, etc. at sensor first-start. Persists to disk so subsequent
restarts see the same universe.

Word sources:
  1. /usr/share/dict/words (wamerican / wbritish package on Debian)
     — 100k+ common English words. Picking random ones means the resulting
     org name is statistically indistinguishable from any natural-English
     two-word name.
  2. Bundled name lists (~400 first names, ~700 last names) for plausible
     person names in customer rosters and ops-team references.
  3. A fallback bundled common-words list if dict/words isn't installed.

Why persist: keeps the universe self-consistent across sensor restarts (an
attacker who reconnects two days later sees the same `bastion.X.internal`,
the same customer roster, the same `~/.aws/credentials` etc).

Why randomize: this deployer repo is public on GitHub. Hardcoded brand
names ("northwind", "havenport", etc.) would let an attacker grep the
repo for the org name they see in the shell and identify it as a honeypot.
Sourcing the org name from /usr/share/dict/words removes that fingerprint.
"""
from __future__ import annotations

import json
import os
import secrets
import string
from pathlib import Path
from typing import Optional


DICT_WORDS_PATH = "/usr/share/dict/words"
_HERE = Path(__file__).resolve().parent
_WORDLIST_DIR = _HERE / "wordlists"


def _load_dict_words(min_len: int = 4, max_len: int = 9) -> list[str]:
    """Read /usr/share/dict/words filtered to plausibly-name-like words.
    Returns a list of lower-case ASCII words. Falls back to the bundled
    common.txt if the system dict isn't available."""
    out: list[str] = []
    src = Path(DICT_WORDS_PATH)
    if src.exists():
        try:
            for raw in src.read_text(encoding="utf-8", errors="ignore").splitlines():
                w = raw.strip()
                if not (min_len <= len(w) <= max_len):
                    continue
                # Filter:
                #   - lowercase only (drops proper nouns and abbreviations)
                #   - ASCII letters only (drops "café", etc.)
                #   - no apostrophes or punctuation
                if not w.isascii() or not w.islower() or not w.isalpha():
                    continue
                out.append(w)
            if len(out) > 500:
                return out
        except Exception:
            pass
    # Fallback to bundled list
    common = _WORDLIST_DIR / "common.txt"
    if common.exists():
        return [w.strip().lower() for w in common.read_text().splitlines() if w.strip()]
    # Absolute last resort
    return ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
            "hotel", "india", "juliet", "kilo", "lima", "mike", "november",
            "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform",
            "victor", "whiskey", "xray", "yankee", "zulu"]


def _load_namelist(filename: str) -> list[str]:
    p = _WORDLIST_DIR / filename
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text().splitlines() if l.strip()]


def _rand_alnum(rng, n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _rand_hex(rng, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _rand_b64(rng, n: int) -> str:
    return "".join(rng.choice(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    ) for _ in range(n))


class FakeWorld:
    """Per-VM random universe. Stable across restarts via on-disk persistence.

    Usage:
        world = FakeWorld.load_or_create(agent_name="kworker-XX",
                                          state_path=Path("/var/lib/.../fake_world.json"))
        world.values["int_domain"]  # e.g. "tanglewood-meridian.internal"
    """

    SCHEMA_VERSION = 1

    def __init__(self, agent_name: str, values: dict) -> None:
        self.agent_name = agent_name
        self.values = values

    # ------------------------------------------------------------- factories
    @classmethod
    def load_or_create(cls, agent_name: str,
                       state_path: Optional[Path] = None) -> "FakeWorld":
        """Load from state_path if present; otherwise generate fresh and save.

        All filesystem I/O is wrapped in try/except so a sensor without write
        access to its data dir, or a missing/corrupt file, still gets a valid
        in-memory universe (regenerated on each start until persistence works).
        """
        if state_path is not None:
            # Don't call .exists() — Python 3.11 propagates PermissionError
            # from underlying stat() instead of returning False. Just try to
            # read and let except handle "not there" the same as "can't read".
            try:
                doc = json.loads(state_path.read_text())
                if doc.get("schema") == cls.SCHEMA_VERSION:
                    return cls(agent_name, doc["values"])
            except Exception:
                pass  # missing, corrupt, or no permission — regenerate

        values = cls._generate(agent_name)
        if state_path is not None:
            try:
                state_path.parent.mkdir(parents=True, exist_ok=True)
                state_path.write_text(json.dumps({
                    "schema": cls.SCHEMA_VERSION,
                    "agent": agent_name,
                    "values": values,
                }, indent=2))
                # Tight perms — sensor user reads it, nothing else
                os.chmod(state_path, 0o640)
            except Exception:
                pass
        return cls(agent_name, values)

    # ----------------------------------------------------------------- gen
    @classmethod
    def _generate(cls, agent_name: str) -> dict:
        rng = secrets.SystemRandom()
        dict_words   = _load_dict_words()
        first_names  = _load_namelist("firstnames.txt") or ["Alex", "Sam", "Jordan"]
        last_names   = _load_namelist("lastnames.txt") or ["Smith", "Garcia", "Kim"]

        # --- org name: pick two dict words. ~100k * 100k = ~10B combinations.
        def _pick_word():
            return rng.choice(dict_words)
        org_w1 = _pick_word()
        org_w2 = _pick_word()
        # Avoid awkward duplicates
        while org_w2 == org_w1:
            org_w2 = _pick_word()
        # Style: random joiner — looks more organic
        joiner = rng.choice(["", "-", ""])  # mostly concatenated, sometimes hyphenated
        org_short = (org_w1 + joiner + org_w2).lower()
        # Common SaaS-style TLDs
        ext_tld = rng.choice(["io", "co", "app", "ai", "cloud", "tech"])
        ext_domain = f"{org_short}.{ext_tld}"
        int_domain = f"{org_short}.internal"

        # --- usernames present on the box (besides root + ubuntu, which are standard)
        # Some are role-based (admin, deploy, ops), some are person-named.
        # The role names are universal Linux conventions, so keeping them is fine;
        # the person-named ones are where we randomize.
        ops_first = rng.choice(first_names)
        ops_last  = rng.choice(last_names)
        dba_first = rng.choice(first_names)
        dba_last  = rng.choice(last_names)

        # --- customer roster: a chunk of random fake customers
        industries = ["logistics", "manufacturing", "retail", "healthcare",
                       "fintech", "shipping", "energy", "pharma", "media",
                       "construction", "agritech", "mobility", "education"]
        country_codes = ["US", "UK", "DE", "FR", "NL", "ES", "IT", "JP", "SG",
                          "BR", "AU", "CA", "MX", "NO", "SE", "ZA", "AE", "PL"]
        plans = ["starter", "growth", "enterprise"]
        plan_value = {"starter": 400, "growth": 1200, "enterprise": 4800}

        def _customer_id():
            return rng.randint(8000, 9999)

        def _customer_company():
            # Combine: word from dict + industry-ish modifier OR word + word
            opts = [
                lambda: f"{_pick_word()}-{rng.choice(industries)}".lower(),
                lambda: f"{_pick_word()} {_pick_word()}".title(),
                lambda: f"{_pick_word()} {rng.choice(['Group', 'Holdings', 'Partners', 'Systems'])}".title(),
            ]
            return rng.choice(opts)()

        customers = []
        seen_ids: set[int] = set()
        for _ in range(rng.randint(10, 14)):
            cid = _customer_id()
            while cid in seen_ids:
                cid = _customer_id()
            seen_ids.add(cid)
            first = rng.choice(first_names).lower()
            last  = rng.choice(last_names).lower().replace("'", "")
            company = _customer_company()
            company_slug = company.lower().replace(" ", "").replace("-", "")
            plan = rng.choices(plans, weights=[2, 3, 5])[0]
            mrr = plan_value[plan] * rng.choice([1, 2, 3])
            customers.append({
                "id": cid,
                "email": f"{first[0]}.{last}@{company_slug}.example",
                "name": f"{first.title()} {last.title()}",
                "company": company,
                "plan": plan,
                "mrr_usd": mrr,
                "country": rng.choice(country_codes),
                "signup_date": f"2024-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
            })

        # --- internal subdomain hosts. The base names (bastion/vault/db) are
        # universal so keeping them is fine.
        ip_oct_a = rng.randint(11, 199)
        ip_oct_b = rng.randint(11, 199)
        while ip_oct_b == ip_oct_a:
            ip_oct_b = rng.randint(11, 199)

        # --- bait file names. We randomize the filenames so attackers can't
        # grep the deployer repo for "vault-export.docx".
        canary_doc_pool = [
            "vault-export", "keys-rotation", "prod-secrets", "infra-handover",
            "credentials-backup", "key-archive", "ops-transfer", "secrets-Q1",
            "secrets-Q2", "ops-rotation", "tokens-snapshot", "key-vault",
        ]
        canary_xls_pool = [
            "customer-dump", "billing-export", "users-rollup", "mrr-report",
            "billing-snapshot", "accounts-export", "customers-Q1", "renewals-list",
        ]
        notes_filename_pool = [
            "notes.txt", "todo.txt", "personal.txt", "scratch.txt", "rotation.txt",
            "handoff.md", "memo.txt",
        ]
        passwords_filename_pool = [
            "passwords.txt", "creds.txt", "rotation.txt", "logins.txt",
            "wifi-codes.txt", "old-passwords.txt",
        ]

        canary_doc_name = rng.choice(canary_doc_pool)
        canary_xls_name = rng.choice(canary_xls_pool)
        canary_doc_backup_name = rng.choice([n for n in canary_doc_pool if n != canary_doc_name])
        notes_filename = rng.choice(notes_filename_pool)
        passwords_filename = rng.choice(passwords_filename_pool)

        # --- "Joe Halpern is the DB owner" style references in notes & runbook
        # Pick one ops-lead persona referenced consistently across files.
        ops_full = f"{ops_first} {ops_last}"
        dba_full = f"{dba_first} {dba_last}"

        # --- which template variant we use for the notes file
        notes_template_id = rng.randint(0, 4)
        passwords_template_id = rng.randint(0, 3)

        # --- secrets / tokens
        aws_account = "".join(str(rng.randint(0, 9)) for _ in range(12))

        return {
            # branding
            "org_short":    org_short,
            "ext_domain":   ext_domain,
            "int_domain":   int_domain,

            # network
            "ip_oct_a":     ip_oct_a,
            "ip_oct_b":     ip_oct_b,

            # people
            "ops_first":    ops_first,
            "ops_last":     ops_last,
            "ops_full":     ops_full,
            "dba_first":    dba_first,
            "dba_last":     dba_last,
            "dba_full":     dba_full,
            "ops_email":    f"{ops_first.lower()}.{ops_last.lower()}@{ext_domain}",
            "dba_email":    f"{dba_first.lower()}.{dba_last.lower()}@{ext_domain}",

            # bait file naming
            "canary_doc_name":          canary_doc_name,
            "canary_xls_name":          canary_xls_name,
            "canary_doc_backup_name":   canary_doc_backup_name,
            "notes_filename":           notes_filename,
            "passwords_filename":       passwords_filename,
            "notes_template_id":        notes_template_id,
            "passwords_template_id":    passwords_template_id,

            # secrets — already random, kept stable per-install
            "aws_account_id":   aws_account,
            "aws_key":          "AKIA" + _rand_alnum(rng, 16, string.ascii_uppercase + string.digits),
            "aws_secret":       _rand_b64(rng, 40),
            "aws_key2":         "AKIA" + _rand_alnum(rng, 16, string.ascii_uppercase + string.digits),
            "aws_secret2":      _rand_b64(rng, 40),
            "aws_key3":         "AKIA" + _rand_alnum(rng, 16, string.ascii_uppercase + string.digits),
            "aws_secret3":      _rand_b64(rng, 40),
            "github_pat":       "ghp_" + _rand_alnum(rng, 36),
            "stripe_key":       _rand_alnum(rng, 24),
            "stripe_whsec":     _rand_alnum(rng, 32),
            "k8s_token":        "eyJhbGciOiJSUzI1NiIs" + _rand_b64(rng, 180),
            "jwt_secret":       _rand_b64(rng, 48),
            "admin_token":      _rand_alnum(rng, 40),
            "vault_token":      "hvs." + _rand_alnum(rng, 24),
            "db_pass":          _rand_alnum(rng, 20),
            "db_pass2":         _rand_alnum(rng, 20),
            "redis_pass":       _rand_alnum(rng, 16),
            "smtp_pass":        _rand_alnum(rng, 18),
            "sentry_id":        _rand_hex(rng, 32),
            "sentry_proj":      str(rng.randint(4000000, 6999999)),
            "docker_auth":      _rand_b64(rng, 48),
            "registry_auth":    _rand_b64(rng, 48),
            "ecr_auth":         _rand_b64(rng, 60),
            "slack_t":          _rand_alnum(rng, 7, string.ascii_uppercase + string.digits),
            "slack_b":          _rand_alnum(rng, 7, string.ascii_uppercase + string.digits),
            "slack_k":          _rand_alnum(rng, 24),
            "dd_key":           _rand_hex(rng, 32),
            "dd_app_key":       _rand_hex(rng, 40),

            # ssh key filler
            "key_filler_a":     _rand_b64(rng, 120),
            "key_filler_b":     _rand_b64(rng, 80),
            "key_filler_c":     _rand_b64(rng, 40),
            "cert_filler":      "\n".join(_rand_b64(rng, 64) for _ in range(14)),
            "cert_filler2":     "\n".join(_rand_b64(rng, 64) for _ in range(14)),
            "cert_filler3":     "\n".join(_rand_b64(rng, 64) for _ in range(12)),

            # log PIDs
            "pid1":     str(rng.randint(2000, 9000)),
            "pid2":     str(rng.randint(2000, 9000)),
            "pid3":     str(rng.randint(2000, 9000)),
            "pid4":     str(rng.randint(2000, 9000)),
            "scanner_ip": f"{rng.randint(45, 199)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}",

            # customer roster
            "customers": customers,
        }
