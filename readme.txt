=== WP Core Secure ===
Contributors: digiasylum
Tags: security, hardening, brute force, http headers, login protection
Requires at least: 5.0
Tested up to: 6.8
Stable tag: 2.2.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Multi-layer WordPress hardening — brute force protection, HTTP headers, user enumeration blocking. Zero telemetry.

== Description ==

WP Core Secure is a lightweight, zero-telemetry security hardening plugin.
Developed by Digi Asylum (https://digiasylum.com) and Umesh Kumar Sahai.

22 security controls across 5 groups — toggle what you need, click Save.

== Installation ==
1. Upload the `wp-core-secure` folder to `/wp-content/plugins/`
2. Activate through the Plugins menu
3. Go to WP Core Secure in the admin sidebar and configure

== Changelog ==

= 2.2.0 =
* Full plugin refactor into professional multi-file structure
* Separated: constants, htaccess, security, login, headers, api, admin, settings, view, CSS, JS
* CSS and JS moved to dedicated files (admin/css/admin.css, admin/js/admin.js)
* Settings page HTML extracted to admin/views/settings-page.php
* Zero inline styles or inline scripts remain in PHP

= 2.1.0 =
* Brute force login protection
* Block user enumeration
* HTTP Security Headers group
* Protect wp-config.php
* Block REST API users endpoint
* Remove Shortlink tag
* Disable self-pingbacks

= 2.0.0 =
* Complete rewrite — .htaccess writes are event-driven only
* Fixed Hostinger false-positive malware flag
* MDB 7 UI with toggle switches
