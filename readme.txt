# 🛡️ WP Core Secure

### Harden your WordPress site in minutes — no code, no config files, no cloud.

**[📥 Download](#-download) · [✨ Features](#-features) · [⚡ Installation](#-installation) · [🖥️ Server Compatibility](#️-server-compatibility) · [🔄 Changelog](#-changelog)**

---

<!-- Place your banner image here -->

</div>

---

## Why WP Core Secure?

A default WordPress installation ships with a handful of settings that create unnecessary attack surface — XML-RPC open to the internet, no limit on login attempts, usernames exposed through the REST API, no HTTP security headers, PHP executable inside the uploads folder. Most site owners never change these because fixing them properly means editing `wp-config.php`, writing `.htaccess` rules, and knowing exactly which WordPress filters to hook.

**WP Core Secure does all of that for you through a single settings page.**

Toggle what you need, click Save — the plugin writes the correct `.htaccess` rules, hooks the right filters, and sends the right HTTP headers. Deactivate the plugin and everything is cleaned up automatically. No leftover rules, no orphaned database rows.

22 security controls. 5 groups. One page. Zero telemetry.

---

## ✨ Features

### 🔧 Core Hardening

| Control | What It Does |
|---|---|
| **Disable XML-RPC** | Blocks `xmlrpc.php` via WordPress filter and `.htaccess`. Stops brute-force amplification and DDoS pingback attacks. Removes RSD and WLW link tags from `<head>`. |
| **Hide WordPress Version** | Strips the `wp_generator` meta tag, removes the version from RSS feeds, and removes `?ver=` query strings from all enqueued scripts and stylesheets. |
| **Remove Admin Footer Text** | Clears the "Thank you for creating with WordPress" string from the admin footer. |
| **Disable Theme & Plugin Editor** | Sets `DISALLOW_FILE_EDIT` — removes the code editor from the WordPress dashboard so a compromised admin account can't be used to inject code. |
| **Disable Dashboard Updates** | Sets `DISALLOW_FILE_MODS` — blocks plugin, theme, and core updates from the dashboard. Intended for sites maintained manually via WP-CLI or FTP. ⚠️ Also disables automatic security patches. |

### 📁 File System Protection

| Control | What It Does |
|---|---|
| **Block PHP in Uploads** | Writes `<Files *.php> Deny from all</Files>` into `wp-content/uploads/.htaccess`. Uploaded malware cannot execute even if it gets past other defences. Works on Apache and LiteSpeed. |
| **Disable Directory Browsing** | Adds `Options -Indexes` to root `.htaccess`. Visitors cannot list folder contents when no index file exists. |
| **Protect wp-config.php** | Adds `<Files wp-config.php> Deny from all</Files>` to root `.htaccess`. Blocks direct HTTP access to your database credentials file. |

### 🔐 Login Security

| Control | What It Does |
|---|---|
| **Brute Force Protection** | Locks an IP address out for 30 minutes after too many failed login attempts. Attempt threshold is configurable (3–20, default 5). Uses WordPress transients — no extra database tables. Proxy and Cloudflare aware. |
| **Generic Login Errors** | Replaces WordPress's "wrong password" and "unknown username" messages with a single neutral message so attackers cannot confirm valid usernames. |
| **Block User Enumeration** | Redirects `?author=N` URL scans to the homepage (301) and removes the `/wp-json/wp/v2/users` REST endpoint for unauthenticated requests. |

### 🌐 HTTP Security Headers

| Control | Header(s) Sent |
|---|---|
| **Core Security Headers** | `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` · `Content-Security-Policy` · `Permissions-Policy: geolocation=(), microphone=(), camera=()` |
| **Clickjacking Protection** | `X-Frame-Options: SAMEORIGIN` — prevents your site from being embedded in iframes on other domains. |
| **MIME & XSS Protection** | `X-Content-Type-Options: nosniff` · `X-XSS-Protection: 1; mode=block` |
| **Referrer Policy** | `Referrer-Policy: strict-origin-when-cross-origin` — controls how much URL information is passed to external sites. |

### ⚙️ Access & API Control

| Control | What It Does |
|---|---|
| **Restrict REST API to Logged-In Users** | Returns `401 Unauthorized` to all unauthenticated REST API requests. |
| **Block REST API Users Endpoint** | Removes `/wp-json/wp/v2/users` specifically — the most common REST-based username enumeration vector — without locking down the full API. |
| **Disable RSS & Atom Feeds** | Redirects all feed URLs to the homepage and removes feed `<link>` tags from `<head>`. |
| **Remove WP Embed Script** | Dequeues `wp-embed.min.js` from every page load. Safe to enable if you don't use oEmbed blocks. |
| **Remove Shortlink Tag** | Removes `<link rel="shortlink">` from `<head>` and the `Link` HTTP response header. |
| **Disable Self-Pingbacks** | Prevents WordPress from sending pingback notifications to its own posts when you link internally. Eliminates unnecessary database writes. |

---

## 📥 Download

Go to the **[Releases page](https://github.com/digiasylum/wp-core-secure/releases)** and download `wp-core-secure-v2.1.0.zip` from the Assets section of the latest release.

---

## ⚡ Installation

**From ZIP**
1. Download the release ZIP above
2. In WordPress admin go to **Plugins → Add New → Upload Plugin**
3. Upload the ZIP → **Install Now** → **Activate**

**From Git**
```bash
cd wp-content/plugins/
git clone https://github.com/digiasylum/wp-core-secure.git
```
Then activate from **Plugins → Installed Plugins**.

**After activation**
Navigate to **WP Core Secure** in the WordPress admin sidebar, toggle the controls you want to enable, and click **Save Settings**. That's it.

---

## 🖥️ Server Compatibility

| Feature | Apache | LiteSpeed | Nginx |
|---|---|---|---|
| XML-RPC filter (PHP) | ✅ | ✅ | ✅ |
| XML-RPC `.htaccess` block | ✅ | ✅ | ➖ Configure in server block |
| Block PHP in Uploads | ✅ | ✅ | ➖ Configure in server block |
| Directory Browsing | ✅ | ✅ | ➖ Off by default on Nginx |
| Protect wp-config.php | ✅ | ✅ | ➖ Configure in server block |
| HTTP Security Headers | ✅ | ✅ | ✅ |
| Login / Brute Force Protection | ✅ | ✅ | ✅ |
| All other runtime features | ✅ | ✅ | ✅ |

Nginx users: all PHP-based features work on every server type. The `.htaccess` features require equivalent rules in your Nginx server block — see [Nginx docs](https://nginx.org/en/docs/) for the equivalent directives.

---

## 🔧 How .htaccess Management Works

All `.htaccess` modifications use clearly named `BEGIN/END` marker blocks, for example:

```apache
# BEGIN WP-Core-Secure: xmlrpc-block
<Files xmlrpc.php>
    Order Deny,Allow
    Deny from all
</Files>
# END WP-Core-Secure: xmlrpc-block
```

- **Idempotent** — saving the same setting twice never duplicates a block
- **Event-driven** — `.htaccess` is only written when you click Save Settings, never on every page request (this is what prevented false-positive malware flags from hosts like Hostinger in earlier versions)
- **Clean on exit** — deactivating the plugin removes every block it added, leaving your `.htaccess` exactly as it was

---

## 🔄 Changelog

### v2.1.0
- Brute force login protection — IP lockout, configurable attempts (3–20), transient-based, proxy and Cloudflare aware
- Block user enumeration — `?author=` redirect + REST `/wp/v2/users` endpoint removal
- HTTP Security Headers group — HSTS, CSP, Permissions-Policy, X-Frame-Options, nosniff, XSS protection, Referrer-Policy
- Protect `wp-config.php` via `.htaccess`
- Block REST API `/users` endpoint specifically (separate from full API lock)
- Remove Shortlink tag from `<head>` and HTTP response headers
- Disable self-pingbacks
- Developer card in settings page (Digi Asylum & Umesh Kumar Sahai)
- Live ACTIVE badge on each toggle — updates without page reload
- Stats row showing active rules, total features, groups, and external calls

### v2.0.0
- Full rewrite — `.htaccess` writes are now event-driven, never per-request (fixed Hostinger false-positive malware flag)
- BEGIN/END marker blocks for idempotent, cleanly reversible `.htaccess` management
- Plugin deactivation removes all `.htaccess` modifications automatically
- Fixed nested `add_action('init')` inside `init` hook
- PHP execution block now uses `<Files>` directive — works on both Apache and LiteSpeed
- MDB 7 UI with toggle switches, section grouping, and feature descriptions

### v1.5
- Fixed Disable File Editing functionality
- Removed WP-Hide feature

---

## 📋 Requirements

| | Minimum |
|---|---|
| WordPress | 5.0+ |
| PHP | 7.4+ |
| Server | Apache or LiteSpeed (full feature set) · Nginx (PHP features only) |

---

## 🤝 Contributing

Pull requests are welcome. For significant changes please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add: your feature description"`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

**Reporting security vulnerabilities:** Please do not open a public issue. Email **connect@digiasylum.com** directly and we'll respond within 48 hours.

---

## 👨‍💻 Developed By

**[Digi Asylum](https://digiasylum.com)** · Lead Developer: **[Umesh Kumar Sahai](https://www.linkedin.com/in/umeshkumarsahai/)**

📧 [connect@digiasylum.com](mailto:connect@digiasylum.com)

---

## 📄 License

GPL v2 or later — [gnu.org/licenses/gpl-2.0.html](https://www.gnu.org/licenses/gpl-2.0.html)

---

<div align="center">
<sub>If WP Core Secure helped secure your site, a ⭐ on GitHub helps other WordPress developers find it.</sub>
</div>
