=== WP Core Secure ===
Contributors: digiasylum
Tags: security, hardening, brute force, http headers, user enumeration, xmlrpc, login protection
Requires at least: 5.0
Tested up to: 6.8
Stable tag: 2.1.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Multi-layer WordPress hardening — brute force protection, HTTP headers, user enumeration blocking, login security. Zero telemetry.

== Description ==

WP Core Secure is a lightweight, zero-telemetry security hardening plugin with a clean MDB-powered settings panel.
Developed by Digi Asylum (https://digiasylum.com) and Umesh Kumar Sahai.

**22 features across 5 security groups:**

= Core Hardening =
* Disable XML-RPC (filter + .htaccess block)
* Hide WordPress Version (head, feeds, and ?ver= query strings)
* Remove Admin Footer Text
* Disable Theme & Plugin Editor
* Disable Dashboard Updates

= File System Protection =
* Block PHP Execution in Uploads (Apache/LiteSpeed .htaccess)
* Disable Directory Browsing
* Protect wp-config.php via .htaccess

= Login Security =
* Brute Force Login Protection (IP-based lockout, configurable attempts, transient-based — no extra tables)
* Generic Login Error Messages (prevents username confirmation)
* Block User Enumeration (?author= redirect + REST /wp/v2/users removal)

= HTTP Security Headers =
* HSTS + Content-Security-Policy + Permissions-Policy
* Clickjacking Protection (X-Frame-Options: SAMEORIGIN)
* MIME Sniffing + XSS Protection headers
* Referrer Policy

= Access & API Control =
* Restrict Full REST API to Logged-In Users
* Block REST API /wp/v2/users Endpoint
* Disable RSS / Atom Feeds
* Remove WP Embed Script
* Remove Shortlink Tag
* Disable Self-Pingbacks

== What changed in v2.1 vs v2.0 ==
* 12 new features (brute force protection, HTTP headers group, wp-config protection, REST users endpoint block, shortlink removal, self-pingback disable)
* Developer card at top of settings page
* Live ACTIVE badge on toggle without page reload
* Stats row showing active/total rules
* Login attempt lockout count is configurable (3–20)
* ?ver= query string stripped from all asset URLs when "Hide Version" is on
* CSP, HSTS, Permissions-Policy headers added as a group

== Installation ==
1. Upload `wp-core-secure` folder to `/wp-content/plugins/`
2. Activate through the Plugins menu
3. Go to **WP Core Secure** in the admin sidebar
4. Toggle what you need and click **Save Settings**

== Frequently Asked Questions ==

= Will this conflict with caching plugins? =
Security headers are sent via PHP before caching. Most caching plugins preserve response headers set in PHP. Test after enabling header features.

= Does brute force protection use a database table? =
No. It uses WordPress transients (stored in wp_options). No extra tables, no extra dependencies.

= Is this compatible with Nginx? =
Runtime PHP features work everywhere. .htaccess features (PHP block in uploads, directory browsing, wp-config protection, XML-RPC block) only apply on Apache/LiteSpeed. Configure these at the Nginx server block level if needed.

= Will "Disable Dashboard Updates" block security patches? =
Yes. DISALLOW_FILE_MODS blocks automatic core security updates too. The settings page warns you. Only enable on sites you update manually.

== Changelog ==

= 2.1.0 =
* NEW: Brute force login protection (IP lockout, transient-based, configurable attempts)
* NEW: Block user enumeration (?author= scans + REST /wp/v2/users endpoint)
* NEW: HTTP Security Headers group (HSTS, CSP, Permissions-Policy, X-Frame-Options, nosniff, XSS, Referrer-Policy)
* NEW: Protect wp-config.php via .htaccess
* NEW: Block REST API /users endpoint specifically
* NEW: Remove Shortlink tag
* NEW: Disable Self-Pingbacks
* Developer card with Digi Asylum & Umesh Kumar Sahai links
* Live ACTIVE badge toggle (no page reload)
* Stats row on settings page
* ?ver= query string stripping when Hide Version is enabled

= 2.0.0 =
* Complete rewrite — .htaccess writes are now event-driven (save only)
* Added BEGIN/END markers to .htaccess blocks for clean removal
* Deactivation hook removes all .htaccess modifications
* Fixed nested add_action('init') bug
* New MDB 7 UI with toggle switches

= 1.5 =
* Fixed Disable File Editing functionality

== Support ==
Email: connect@digiasylum.com
LinkedIn: https://www.linkedin.com/in/umeshkumarsahai/
