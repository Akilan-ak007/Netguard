# 🔥 NetGuard — CLI Firewall for LAN-wide Control

NetGuard is a **Python-based CLI firewall** designed to enforce domain and category-level blocking across a system or an entire LAN.

It combines **/etc/hosts manipulation, dnsmasq DNS filtering, and iptables enforcement** to deliver a layered, practical firewall solution for real-world environments like college networks, offices, and home labs.

---

## 🚀 Key Capabilities

* 🌐 Block specific domains (e.g. `facebook.com`)
* 🧠 Category-based filtering (social media, gaming, streaming, etc.)
* 🛡️ LAN-wide enforcement using DNS + iptables
* ⚡ Real-time CLI control (block, unblock, apply, flush)
* 📜 Logging system for audit and monitoring
* ✅ Whitelist support (override blocking rules)

---

## 🧩 Architecture Overview

NetGuard operates across **three enforcement layers**:

### 1. Local Blocking

* Updates `/etc/hosts`
* Blocks domains on the host machine

### 2. DNS-Level Filtering

* Integrates with `dnsmasq`
* Redirects blocked domains to `0.0.0.0`
* Enables **LAN-wide filtering**

### 3. Network-Level Enforcement

* Uses `iptables`
* Drops packets to resolved IPs
* Ensures stricter blocking at gateway level

---

## ⚙️ Installation

```bash
git clone https://github.com/inba-web/netguard.git
cd netguard
chmod +x firewall.py

# Optional: make it global CLI
sudo ln -s $(pwd)/firewall.py /usr/local/bin/netguard
```

---

## ▶️ Usage

Run with root privileges:

```bash
sudo netguard <command>
```

---

## 📌 Commands

### Block / Unblock Domains

```bash
sudo netguard block facebook.com instagram.com
sudo netguard unblock facebook.com
```

### Category Control

```bash
sudo netguard category list
sudo netguard category block social_media
sudo netguard category allow gaming
```

### Whitelist Management

```bash
sudo netguard whitelist add youtube.com
sudo netguard whitelist remove youtube.com
sudo netguard whitelist list
```

### Apply Rules

```bash
sudo netguard apply
```

Enable LAN-wide enforcement:

```bash
sudo netguard apply --lan
```

### Flush All Rules

```bash
sudo netguard flush
```

### Status & Monitoring

```bash
netguard status
netguard list
netguard logs
```

---

## 🧠 Configuration

Config file:

```
/etc/netguard/config.json
```

Includes:

* blocked domains
* blocked categories
* whitelist
* LAN interface
* ports

---

## 🌍 LAN-Wide Setup (Important)

To enforce rules across all devices:

1. Install dnsmasq

```bash
sudo apt install dnsmasq
```

2. Set this machine as DNS server in router/DHCP

3. Enable forwarding (auto with `--lan`)

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

4. Apply rules:

```bash
sudo netguard apply --lan
```

---

## 📂 Logs

```
/var/log/netguard.log
```

Tracks:

* blocked domains
* allowed/whitelisted actions
* rule applications

---

## ⚠️ Requirements

* Linux (Kali / Ubuntu recommended)
* Root access (`sudo`)
* `iptables`
* `dnsmasq` (for LAN mode)

---

## 🛣️ Roadmap

* [ ] Future enhancements planned to expand NetGuard’s capabilities and usability:
* [ ] HTTPS/SNI filtering
* [ ] Web dashboard (React + API)
* [ ] Real-time traffic monitoring
* [ ] Dockerized deployment
* [ ] Rule scheduling (time-based blocking)

---

## 💼 Use Cases

* College / hostel network control
* Office productivity enforcement
* Parental control system
* Cybersecurity lab experimentation

---

## 👨‍💻 Author

**Inba**
Cybersecurity & Full-Stack Developer

---

## 📜 License

MIT License

---

## ⭐ Project Vision

NetGuard is designed to evolve into a **lightweight open-source firewall platform**, bridging the gap between simple host blocking and enterprise-grade network control.
