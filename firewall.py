#!/usr/bin/env python3
"""
NetGuard CLI Firewall
- Blocks URLs and content categories (social media, gaming, etc.)
- Acts as a DNS/proxy firewall for the entire LAN
- Run as root on the gateway machine in your network
"""

import argparse
import json
import os
import sys
import signal
import subprocess
import socket
import threading
import time
import re
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

CONFIG_DIR = Path("/etc/netguard")
CONFIG_FILE = CONFIG_DIR / "config.json"
LOG_FILE = Path("/var/log/netguard.log")

DEFAULT_CONFIG = {
    "blocked_domains": [],
    "blocked_categories": [],
    "whitelist": [],
    "dns_port": 53,
    "proxy_port": 8080,
    "lan_interface": "eth0",
    "log_blocked": True,
}

CATEGORY_DOMAINS = {
    "social_media": [
        "facebook.com", "www.facebook.com", "m.facebook.com",
        "instagram.com", "www.instagram.com",
        "twitter.com", "www.twitter.com", "x.com", "www.x.com",
        "tiktok.com", "www.tiktok.com",
        "snapchat.com", "www.snapchat.com",
        "reddit.com", "www.reddit.com", "old.reddit.com",
        "pinterest.com", "www.pinterest.com",
        "tumblr.com", "www.tumblr.com",
        "linkedin.com", "www.linkedin.com",
        "discord.com", "www.discord.com", "discordapp.com",
        "telegram.org", "web.telegram.org",
        "whatsapp.com", "web.whatsapp.com",
        "vk.com", "www.vk.com",
        "weibo.com", "www.weibo.com",
        "threads.net", "www.threads.net",
        "mastodon.social",
        "twitch.tv", "www.twitch.tv",
        "clubhouse.com",
    ],
    "gaming": [
        "steampowered.com", "store.steampowered.com", "steamcommunity.com",
        "epicgames.com", "www.epicgames.com",
        "roblox.com", "www.roblox.com",
        "minecraft.net", "www.minecraft.net",
        "battle.net", "us.battle.net",
        "ea.com", "www.ea.com", "origin.com",
        "ubisoft.com", "www.ubisoft.com",
        "leagueoflegends.com", "www.leagueoflegends.com",
        "dota2.com", "www.dota2.com",
        "fortnite.com", "www.fortnite.com",
        "activision.com", "www.activision.com",
        "gog.com", "www.gog.com",
        "itch.io", "www.itch.io",
        "twitch.tv", "www.twitch.tv",
        "kongregate.com", "www.kongregate.com",
        "miniclip.com", "www.miniclip.com",
        "poki.com", "www.poki.com",
        "friv.com", "www.friv.com",
        "addictinggames.com",
        "armor games", "armorgames.com",
        "coolmathgames.com",
        "gameflare.com",
    ],
    "streaming": [
        "netflix.com", "www.netflix.com",
        "youtube.com", "www.youtube.com", "youtu.be",
        "primevideo.com", "www.primevideo.com",
        "hulu.com", "www.hulu.com",
        "disneyplus.com", "www.disneyplus.com",
        "hbomax.com", "www.hbomax.com", "max.com",
        "peacocktv.com", "www.peacocktv.com",
        "crunchyroll.com", "www.crunchyroll.com",
        "vimeo.com", "www.vimeo.com",
        "dailymotion.com", "www.dailymotion.com",
        "twitch.tv", "www.twitch.tv",
        "spotify.com", "open.spotify.com",
        "soundcloud.com", "www.soundcloud.com",
        "pandora.com", "www.pandora.com",
        "deezer.com", "www.deezer.com",
        "bilibili.com", "www.bilibili.com",
    ],
    "adult": [
        "pornhub.com", "www.pornhub.com",
        "xvideos.com", "www.xvideos.com",
        "xnxx.com", "www.xnxx.com",
        "redtube.com", "www.redtube.com",
        "youporn.com", "www.youporn.com",
        "onlyfans.com", "www.onlyfans.com",
        "chaturbate.com", "www.chaturbate.com",
        "xhamster.com", "www.xhamster.com",
    ],
    "gambling": [
        "bet365.com", "www.bet365.com",
        "pokerstars.com", "www.pokerstars.com",
        "draftkings.com", "www.draftkings.com",
        "fanduel.com", "www.fanduel.com",
        "betway.com", "www.betway.com",
        "888casino.com",
        "bovada.lv",
        "casinoroom.com",
        "unibet.com",
        "williamhill.com",
    ],
    "shopping": [
        "amazon.com", "www.amazon.com",
        "ebay.com", "www.ebay.com",
        "walmart.com", "www.walmart.com",
        "aliexpress.com", "www.aliexpress.com",
        "alibaba.com", "www.alibaba.com",
        "shopify.com",
        "etsy.com", "www.etsy.com",
        "flipkart.com", "www.flipkart.com",
        "myntra.com", "www.myntra.com",
        "meesho.com", "www.meesho.com",
        "snapdeal.com", "www.snapdeal.com",
    ],
}

# ──────────────────────────────────────────────
# COLORS
# ──────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""
{C.DIM}  ┌──────────────────────────────────────────────────────────────────────────┐{C.RESET}
{C.DIM}  │{C.RESET}                                                                          {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}              {C.CYAN}▀█▀ █▀▀ █▀▀ █░█ █▄░█ █▀█ █░░ █▀█ █▀▀ █▄█{C.RESET}              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}              {C.CYAN}░█░ ██▄ █▄▄ █▀█ █░▀█ █▄█ █▄▄ █▄█ █▄█ ░█░{C.RESET}              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                                                                          {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}╔═══════════════════╗{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}║{C.CYAN}  ╔─────────────╗  {C.WHITE}║{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}║{C.CYAN}  │{C.GREEN}  ▄▄▄▄▄▄▄▄▄  {C.CYAN}│  {C.WHITE}║{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}║{C.CYAN}  │{C.GREEN}  █ N·E·T █  {C.CYAN}│  {C.WHITE}║{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}║{C.CYAN}  │{C.GREEN}  █ GUARD █  {C.CYAN}│  {C.WHITE}║{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}║{C.CYAN}  │{C.GREEN}  ▀▀▀▀▀▀▀▀▀  {C.CYAN}│  {C.WHITE}║{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}║{C.CYAN}  │{C.DIM}  ───────────  {C.CYAN}│  {C.WHITE}║{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}║{C.CYAN}  │{C.RED}  [■] BLOCK  {C.CYAN}│  {C.WHITE}║{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}║{C.CYAN}  │{C.GREEN}  [✓] ALLOW  {C.CYAN}│  {C.WHITE}║{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}║{C.CYAN}  │{C.DIM}  ───────────  {C.CYAN}│  {C.WHITE}║{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}║{C.CYAN}  │{C.CYAN}  DNS·IPT·HO  {C.CYAN}│  {C.WHITE}║{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}║{C.CYAN}  ╚─────────────╝  {C.WHITE}║{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}╠═══════════════════╣{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}║{C.DIM}  v1.0  ·  LAN MODE  {C.WHITE}║{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                   {C.WHITE}╚═══════════════════╝{C.RESET}                              {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                          {C.DIM}│{C.RESET}                                             {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}              {C.DIM}───────────┴───────────{C.RESET}                                   {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}              {C.RED}▓{C.RESET}{C.DIM}  DNS  ·  IPTABLES  ·  HOSTS  {C.RESET}{C.RED}▓{C.RESET}                         {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}              {C.DIM}───────────────────────{C.RESET}                                   {C.DIM}│{C.RESET}
{C.DIM}  │{C.RESET}                                                                          {C.DIM}│{C.RESET}
{C.DIM}  └──────────────────────────────────────────────────────────────────────────┘{C.RESET}
{C.BOLD}{C.WHITE}
    ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗{C.RESET}{C.BOLD}{C.CYAN}
    ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║{C.RESET}{C.BOLD}{C.RED}
    ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝{C.RESET}
{C.DIM}    ─────────────────────────────────────────────────────────────────────{C.RESET}
{C.DIM}                  CLI Firewall  ·  LAN-wide  ·  DNS + IPTables{C.RESET}
{C.DIM}    ─────────────────────────────────────────────────────────────────────{C.RESET}
""")

def ok(msg):   print(f"  {C.GREEN}✓{C.RESET} {msg}")
def err(msg):  print(f"  {C.RED}✗{C.RESET} {msg}")
def info(msg): print(f"  {C.BLUE}→{C.RESET} {msg}")
def warn(msg): print(f"  {C.YELLOW}⚠{C.RESET} {msg}")

# ──────────────────────────────────────────────
# CONFIG HELPERS
# ──────────────────────────────────────────────

def load_config():
    if not CONFIG_FILE.exists():
        return dict(DEFAULT_CONFIG)
    with open(CONFIG_FILE) as f:
        cfg = json.load(f)
    # merge any missing keys
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    return cfg

def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

def require_root():
    if os.geteuid() != 0:
        err("This command requires root privileges. Run with sudo.")
        sys.exit(1)

def log_event(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except Exception:
        pass

# ──────────────────────────────────────────────
# IPTABLES / HOSTS BLOCKING ENGINE
# ──────────────────────────────────────────────

HOSTS_MARKER_START = "# === NETGUARD BLOCK START ==="
HOSTS_MARKER_END   = "# === NETGUARD BLOCK END ==="

def get_all_blocked_domains(cfg):
    domains = set(cfg.get("blocked_domains", []))
    for cat in cfg.get("blocked_categories", []):
        for d in CATEGORY_DOMAINS.get(cat, []):
            domains.add(d)
    whitelist = set(cfg.get("whitelist", []))
    return domains - whitelist

def apply_hosts_block(cfg):
    """Block domains via /etc/hosts (works for local machine)."""
    blocked = get_all_blocked_domains(cfg)
    hosts_path = Path("/etc/hosts")
    content = hosts_path.read_text()

    # Remove old block
    if HOSTS_MARKER_START in content:
        start = content.index(HOSTS_MARKER_START)
        end   = content.index(HOSTS_MARKER_END) + len(HOSTS_MARKER_END)
        content = content[:start].rstrip() + "\n" + content[end:].lstrip()

    # Build new block
    lines = [HOSTS_MARKER_START]
    for domain in sorted(blocked):
        lines.append(f"0.0.0.0 {domain}")
        if not domain.startswith("www."):
            lines.append(f"0.0.0.0 www.{domain}")
    lines.append(HOSTS_MARKER_END)

    content = content.rstrip() + "\n\n" + "\n".join(lines) + "\n"
    hosts_path.write_text(content)
    return len(blocked)

def clear_hosts_block():
    hosts_path = Path("/etc/hosts")
    content = hosts_path.read_text()
    if HOSTS_MARKER_START in content:
        start = content.index(HOSTS_MARKER_START)
        end   = content.index(HOSTS_MARKER_END) + len(HOSTS_MARKER_END)
        content = content[:start].rstrip() + "\n" + content[end:].lstrip()
        hosts_path.write_text(content)

def run_cmd(cmd, silent=False):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if not silent and result.returncode != 0:
        warn(f"Command failed: {cmd}\n    {result.stderr.strip()}")
    return result.returncode == 0

def apply_iptables_lan(cfg):
    """
    Set up iptables rules so that ALL LAN traffic through this machine is filtered.
    Requires this machine to be the gateway/router for the LAN.
    """
    iface = cfg.get("lan_interface", "eth0")
    blocked = get_all_blocked_domains(cfg)

    # Enable IP forwarding
    run_cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    run_cmd("sysctl -w net.ipv4.ip_forward=1 -q")

    # Enable NAT masquerade (so this machine routes for LAN)
    run_cmd(f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE")

    # Allow established connections
    run_cmd("iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    # Insert drop rules for each blocked domain IP
    # NOTE: domain->IP resolution happens at rule application time
    dropped = 0
    for domain in sorted(blocked):
        try:
            ip = socket.gethostbyname(domain)
            run_cmd(f'iptables -I FORWARD -d {ip} -j DROP -m comment --comment "netguard:{domain}"', silent=True)
            run_cmd(f'iptables -I OUTPUT  -d {ip} -j DROP -m comment --comment "netguard:{domain}"', silent=True)
            dropped += 1
        except socket.gaierror:
            pass

    return dropped

def flush_iptables_netguard():
    """Remove all netguard iptables rules."""
    # List all rules with line numbers, find netguard ones, delete them
    for chain in ["FORWARD", "OUTPUT"]:
        result = subprocess.run(
            f"iptables -L {chain} --line-numbers -n",
            shell=True, capture_output=True, text=True
        )
        lines = result.stdout.splitlines()
        # Collect line numbers to delete (in reverse to avoid shifting)
        to_delete = []
        for line in lines:
            if "netguard:" in line:
                num = line.split()[0]
                if num.isdigit():
                    to_delete.append(int(num))
        for num in sorted(to_delete, reverse=True):
            run_cmd(f"iptables -D {chain} {num}", silent=True)

# ──────────────────────────────────────────────
# DNS BLOCKING (dnsmasq integration)
# ──────────────────────────────────────────────

DNSMASQ_CONF = Path("/etc/dnsmasq.d/netguard.conf")

def apply_dnsmasq_block(cfg):
    """Write dnsmasq block config — best LAN-wide blocking method."""
    blocked = get_all_blocked_domains(cfg)
    lines = ["# NetGuard DNS Block — auto-generated, do not edit"]
    for domain in sorted(blocked):
        lines.append(f"address=/{domain}/0.0.0.0")
        lines.append(f"address=/{domain}/::")
    DNSMASQ_CONF.parent.mkdir(parents=True, exist_ok=True)
    DNSMASQ_CONF.write_text("\n".join(lines) + "\n")
    # Reload dnsmasq if running
    run_cmd("systemctl reload dnsmasq 2>/dev/null || service dnsmasq reload 2>/dev/null", silent=True)
    return len(blocked)

def clear_dnsmasq_block():
    if DNSMASQ_CONF.exists():
        DNSMASQ_CONF.unlink()
    run_cmd("systemctl reload dnsmasq 2>/dev/null || service dnsmasq reload 2>/dev/null", silent=True)

# ──────────────────────────────────────────────
# CLI COMMANDS
# ──────────────────────────────────────────────

def cmd_status(args):
    cfg = load_config()
    print(f"\n{C.BOLD}NetGuard Status{C.RESET}")
    print("─" * 40)

    blocked_domains = cfg.get("blocked_domains", [])
    blocked_cats    = cfg.get("blocked_categories", [])
    whitelist       = cfg.get("whitelist", [])
    all_blocked     = get_all_blocked_domains(cfg)

    print(f"  Custom blocked domains : {C.RED}{len(blocked_domains)}{C.RESET}")
    print(f"  Blocked categories     : {C.RED}{len(blocked_cats)}{C.RESET}")
    if blocked_cats:
        for c in blocked_cats:
            print(f"      {C.DIM}• {c}{C.RESET}")
    print(f"  Whitelisted domains    : {C.GREEN}{len(whitelist)}{C.RESET}")
    print(f"  Total blocked domains  : {C.BOLD}{C.RED}{len(all_blocked)}{C.RESET}")
    print(f"  LAN interface          : {cfg.get('lan_interface')}")
    print(f"  DNS conf               : {'active' if DNSMASQ_CONF.exists() else C.DIM+'not applied'+C.RESET}")
    print(f"  /etc/hosts block       : {'active' if HOSTS_MARKER_START in Path('/etc/hosts').read_text() else C.DIM+'not applied'+C.RESET}")
    print()

def cmd_block(args):
    require_root()
    cfg = load_config()
    domains = cfg.setdefault("blocked_domains", [])
    added = []
    for domain in args.domains:
        domain = domain.lower().strip()
        if domain not in domains:
            domains.append(domain)
            added.append(domain)
    save_config(cfg)
    for d in added:
        ok(f"Blocked: {C.RED}{d}{C.RESET}")
        log_event(f"BLOCKED domain: {d}")
    if not added:
        warn("All specified domains were already blocked.")

def cmd_unblock(args):
    require_root()
    cfg = load_config()
    domains = cfg.get("blocked_domains", [])
    removed = []
    for domain in args.domains:
        domain = domain.lower().strip()
        if domain in domains:
            domains.remove(domain)
            removed.append(domain)
    cfg["blocked_domains"] = domains
    save_config(cfg)
    for d in removed:
        ok(f"Unblocked: {C.GREEN}{d}{C.RESET}")
        log_event(f"UNBLOCKED domain: {d}")
    if not removed:
        warn("None of those domains were in the block list.")

def cmd_category(args):
    require_root()
    cfg = load_config()
    cats = cfg.setdefault("blocked_categories", [])
    available = list(CATEGORY_DOMAINS.keys())

    if args.action == "list":
        print(f"\n{C.BOLD}Available Categories:{C.RESET}")
        for cat in available:
            count  = len(CATEGORY_DOMAINS[cat])
            active = C.RED + "BLOCKED" + C.RESET if cat in cats else C.DIM + "allowed" + C.RESET
            print(f"  {C.CYAN}{cat:<20}{C.RESET}  {count:>3} domains   [{active}]")
        print()
        return

    for cat in args.categories:
        cat = cat.lower().strip()
        if cat not in available:
            err(f"Unknown category: {cat}. Use: {', '.join(available)}")
            continue
        if args.action == "block":
            if cat not in cats:
                cats.append(cat)
                ok(f"Category blocked: {C.RED}{cat}{C.RESET} ({len(CATEGORY_DOMAINS[cat])} domains)")
                log_event(f"BLOCKED category: {cat}")
            else:
                warn(f"Category already blocked: {cat}")
        elif args.action == "allow":
            if cat in cats:
                cats.remove(cat)
                ok(f"Category allowed: {C.GREEN}{cat}{C.RESET}")
                log_event(f"ALLOWED category: {cat}")
            else:
                warn(f"Category was not blocked: {cat}")

    cfg["blocked_categories"] = cats
    save_config(cfg)

def cmd_whitelist(args):
    require_root()
    cfg = load_config()
    wl = cfg.setdefault("whitelist", [])

    if args.action == "add":
        for domain in args.domains:
            domain = domain.lower().strip()
            if domain not in wl:
                wl.append(domain)
                ok(f"Whitelisted: {C.GREEN}{domain}{C.RESET}")
                log_event(f"WHITELISTED: {domain}")
    elif args.action == "remove":
        for domain in args.domains:
            domain = domain.lower().strip()
            if domain in wl:
                wl.remove(domain)
                ok(f"Removed from whitelist: {domain}")
    elif args.action == "list":
        if wl:
            print(f"\n{C.BOLD}Whitelisted Domains:{C.RESET}")
            for d in wl:
                print(f"  {C.GREEN}✓{C.RESET} {d}")
        else:
            info("Whitelist is empty.")
        print()
        return

    cfg["whitelist"] = wl
    save_config(cfg)

def cmd_apply(args):
    require_root()
    cfg = load_config()
    all_blocked = get_all_blocked_domains(cfg)

    print(f"\n{C.BOLD}Applying firewall rules...{C.RESET}")
    print(f"  Total domains to block: {C.RED}{C.BOLD}{len(all_blocked)}{C.RESET}\n")

    # 1. /etc/hosts (localhost)
    n = apply_hosts_block(cfg)
    ok(f"/etc/hosts updated ({n} domain entries)")

    # 2. dnsmasq (LAN-wide DNS)
    try:
        n = apply_dnsmasq_block(cfg)
        ok(f"dnsmasq config written ({n} domains) → {DNSMASQ_CONF}")
    except Exception as e:
        warn(f"dnsmasq config failed: {e}")

    # 3. iptables (LAN gateway)
    if args.lan:
        info("Applying iptables LAN forwarding rules (this may take a moment)...")
        n = apply_iptables_lan(cfg)
        ok(f"iptables: {n} domain IPs blocked in FORWARD chain")

    log_event(f"APPLIED rules: {len(all_blocked)} domains, lan={args.lan}")
    print(f"\n{C.GREEN}{C.BOLD}  ✓ Firewall rules applied!{C.RESET}")

    if not args.lan:
        print(f"\n{C.YELLOW}  Tip:{C.RESET} For LAN-wide blocking, run: {C.CYAN}sudo netguard apply --lan{C.RESET}")
    print()
    _print_lan_setup_tip(cfg)

def cmd_flush(args):
    require_root()
    print(f"\n{C.BOLD}Flushing all NetGuard rules...{C.RESET}")
    clear_hosts_block()
    ok("/etc/hosts block cleared")
    clear_dnsmasq_block()
    ok("dnsmasq config removed")
    flush_iptables_netguard()
    ok("iptables rules flushed")
    log_event("FLUSHED all rules")
    print()

def cmd_list(args):
    cfg = load_config()
    domains = cfg.get("blocked_domains", [])
    cats    = cfg.get("blocked_categories", [])

    print(f"\n{C.BOLD}Custom Blocked Domains:{C.RESET}")
    if domains:
        for d in sorted(domains):
            print(f"  {C.RED}✗{C.RESET} {d}")
    else:
        info("No custom domains blocked.")

    print(f"\n{C.BOLD}Blocked Categories:{C.RESET}")
    if cats:
        for c in cats:
            print(f"  {C.RED}✗{C.RESET} {c}  {C.DIM}({len(CATEGORY_DOMAINS.get(c,[]))} domains){C.RESET}")
    else:
        info("No categories blocked.")
    print()

def cmd_logs(args):
    n = args.lines or 50
    if not LOG_FILE.exists():
        info("No log file found yet.")
        return
    lines = LOG_FILE.read_text().splitlines()
    recent = lines[-n:]
    print(f"\n{C.BOLD}Recent NetGuard Events (last {n}):{C.RESET}")
    for line in recent:
        if "BLOCKED" in line:
            print(f"  {C.RED}{line}{C.RESET}")
        elif "ALLOWED" in line or "WHITELISTED" in line or "UNBLOCKED" in line:
            print(f"  {C.GREEN}{line}{C.RESET}")
        else:
            print(f"  {C.DIM}{line}{C.RESET}")
    print()

def cmd_setup(args):
    """Print LAN gateway setup instructions."""
    banner()
    _print_lan_setup_tip(load_config(), full=True)

def _print_lan_setup_tip(cfg, full=False):
    iface = cfg.get("lan_interface", "eth0")
    print(f"""{C.BOLD}  ── LAN-wide Blocking Setup ──{C.RESET}

  For ALL devices on your college/office network to be filtered:
  This machine must be the {C.CYAN}default gateway{C.RESET} for the LAN.

  {C.BOLD}Step 1:{C.RESET} Install dnsmasq
    {C.DIM}sudo apt install dnsmasq{C.RESET}

  {C.BOLD}Step 2:{C.RESET} Set this machine's IP as DNS server on the router
    (or configure DHCP to hand out this machine's IP as DNS)

  {C.BOLD}Step 3:{C.RESET} Enable IP forwarding (done automatically by --lan flag)
    {C.DIM}sudo sysctl -w net.ipv4.ip_forward=1{C.RESET}

  {C.BOLD}Step 4:{C.RESET} Apply rules with LAN mode
    {C.DIM}sudo netguard apply --lan{C.RESET}

  {C.BOLD}Interface detected:{C.RESET} {C.CYAN}{iface}{C.RESET}
  Change with: {C.DIM}sudo netguard config --interface <eth0|wlan0|...>{C.RESET}
""")

def cmd_config(args):
    require_root()
    cfg = load_config()
    if args.interface:
        cfg["lan_interface"] = args.interface
        save_config(cfg)
        ok(f"LAN interface set to: {args.interface}")

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    banner()
    parser = argparse.ArgumentParser(
        prog="netguard",
        description="NetGuard — CLI Firewall for LAN-wide URL & category blocking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", title="commands")

    # block
    p = sub.add_parser("block", help="Block specific domain(s)")
    p.add_argument("domains", nargs="+", metavar="DOMAIN", help="e.g. example.com")
    p.set_defaults(func=cmd_block)

    # unblock
    p = sub.add_parser("unblock", help="Unblock specific domain(s)")
    p.add_argument("domains", nargs="+", metavar="DOMAIN")
    p.set_defaults(func=cmd_unblock)

    # category
    p = sub.add_parser("category", help="Block/allow entire categories")
    p.add_argument("action", choices=["block", "allow", "list"])
    p.add_argument("categories", nargs="*", metavar="CATEGORY",
                   help="social_media, gaming, streaming, adult, gambling, shopping")
    p.set_defaults(func=cmd_category)

    # whitelist
    p = sub.add_parser("whitelist", help="Manage whitelist (always-allow)")
    p.add_argument("action", choices=["add", "remove", "list"])
    p.add_argument("domains", nargs="*", metavar="DOMAIN")
    p.set_defaults(func=cmd_whitelist)

    # apply
    p = sub.add_parser("apply", help="Push rules to system (hosts + dnsmasq + iptables)")
    p.add_argument("--lan", action="store_true", help="Also apply iptables LAN gateway rules")
    p.set_defaults(func=cmd_apply)

    # flush
    p = sub.add_parser("flush", help="Remove all NetGuard rules from the system")
    p.set_defaults(func=cmd_flush)

    # list
    p = sub.add_parser("list", help="List all blocked domains and categories")
    p.set_defaults(func=cmd_list)

    # status
    p = sub.add_parser("status", help="Show firewall status summary")
    p.set_defaults(func=cmd_status)

    # logs
    p = sub.add_parser("logs", help="View recent firewall log events")
    p.add_argument("-n", "--lines", type=int, default=50, help="Number of lines to show")
    p.set_defaults(func=cmd_logs)

    # config
    p = sub.add_parser("config", help="Set configuration options")
    p.add_argument("--interface", metavar="IFACE", help="LAN interface (e.g. eth0, wlan0)")
    p.set_defaults(func=cmd_config)

    # setup
    p = sub.add_parser("setup", help="Print LAN gateway setup instructions")
    p.set_defaults(func=cmd_setup)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        print()
        return

    if hasattr(args, "func"):
        args.func(args)

if __name__ == "__main__":
    main()