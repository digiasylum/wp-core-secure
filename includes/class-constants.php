<?php
/**
 * WPCS_Constants
 *
 * Central registry for all option keys, slugs, and feature key lists.
 * Any class that needs a shared key imports it from here — no magic strings
 * scattered across the codebase.
 *
 * @package WPCoreSecure
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPCS_Constants {

    /** WordPress option name where settings are stored */
    const OPTION_KEY = 'wpcs_settings';

    /** Settings group name used with register_setting() */
    const SETTINGS_GROUP = 'wpcs_group';

    /** Admin menu slug */
    const MENU_SLUG = 'wpcs-settings';

    /** Transient key prefix for brute force tracking (append hashed IP) */
    const TRANSIENT_PREFIX = 'wpcs_login_attempts_';

    /** Brute force lockout duration in seconds (30 minutes) */
    const LOCKOUT_DURATION = 1800;

    /**
     * Master list of all boolean feature keys saved in wpcs_settings.
     * Used by the sanitizer to whitelist keys and by the UI to build cards.
     *
     * @return string[]
     */
    public static function feature_keys() {
        return [
            // Core Hardening
            'disable_xmlrpc',
            'hide_version',
            'hide_footer_message',
            'disable_file_editing',
            'disable_updates',

            // File System
            'disable_php_execution',
            'disable_directory_browsing',
            'protect_wpconfig',

            // Login Security
            'login_limit',
            'generic_login_errors',
            'disable_login_hints',
            'block_user_enumeration',

            // HTTP Security Headers
            'security_headers',
            'clickjacking_protection',
            'content_type_nosniff',
            'referrer_policy',

            // Access & API Control
            'disable_rest_api_for_guests',
            'block_rest_users_endpoint',
            'disable_rss',
            'remove_wp_embed',
            'remove_shortlink',
            'disable_self_pingbacks',
        ];
    }

    /**
     * Section definitions used by both the UI renderer and the feature map.
     * Each section contains a label, icon, and list of feature keys in order.
     *
     * @return array[]
     */
    public static function sections() {
        return [
            [
                'label'    => 'Core Hardening',
                'icon'     => 'fa-screwdriver-wrench',
                'features' => [
                    'disable_xmlrpc',
                    'hide_version',
                    'hide_footer_message',
                    'disable_file_editing',
                    'disable_updates',
                ],
            ],
            [
                'label'    => 'File System Protection',
                'icon'     => 'fa-folder-tree',
                'features' => [
                    'disable_php_execution',
                    'disable_directory_browsing',
                    'protect_wpconfig',
                ],
            ],
            [
                'label'    => 'Login Security',
                'icon'     => 'fa-lock',
                'features' => [
                    'login_limit',
                    'generic_login_errors',
                    'disable_login_hints',
                    'block_user_enumeration',
                ],
            ],
            [
                'label'    => 'HTTP Security Headers',
                'icon'     => 'fa-tower-broadcast',
                'features' => [
                    'security_headers',
                    'clickjacking_protection',
                    'content_type_nosniff',
                    'referrer_policy',
                ],
            ],
            [
                'label'    => 'Access &amp; API Control',
                'icon'     => 'fa-sliders',
                'features' => [
                    'disable_rest_api_for_guests',
                    'block_rest_users_endpoint',
                    'disable_rss',
                    'remove_wp_embed',
                    'remove_shortlink',
                    'disable_self_pingbacks',
                ],
            ],
        ];
    }

    /**
     * Full feature metadata: icon, colour class, label, description, warning.
     * Keeping this here means the admin view has zero hardcoded strings.
     *
     * @return array[]
     */
    public static function feature_meta() {
        return [
            'disable_xmlrpc' => [
                'icon'  => 'fa-plug-circle-xmark',
                'ic'    => 'ic-red',
                'label' => 'Disable XML-RPC',
                'desc'  => 'Blocks <code>xmlrpc.php</code> via WordPress filter and <code>.htaccess</code>. Stops brute-force amplification and DDoS pingback attacks. Also removes RSD and WLW link tags from <code>&lt;head&gt;</code>.',
                'warn'  => '',
            ],
            'hide_version' => [
                'icon'  => 'fa-eye-slash',
                'ic'    => 'ic-blue',
                'label' => 'Hide WordPress Version',
                'desc'  => 'Removes the <code>wp_generator</code> meta tag, strips version from RSS feeds, and removes <code>?ver=</code> query strings from all enqueued scripts and stylesheets.',
                'warn'  => '',
            ],
            'hide_footer_message' => [
                'icon'  => 'fa-comment-slash',
                'ic'    => 'ic-slate',
                'label' => 'Remove Admin Footer Text',
                'desc'  => 'Clears the "Thank you for creating with WordPress" string and WP version number from the admin footer — minor fingerprinting reduction.',
                'warn'  => '',
            ],
            'disable_file_editing' => [
                'icon'  => 'fa-file-pen',
                'ic'    => 'ic-orange',
                'label' => 'Disable Theme &amp; Plugin Editor',
                'desc'  => 'Sets <code>DISALLOW_FILE_EDIT</code> to remove the in-dashboard code editor. If an admin account is compromised, attackers cannot inject code through the UI.',
                'warn'  => '',
            ],
            'disable_updates' => [
                'icon'  => 'fa-ban',
                'ic'    => 'ic-red',
                'label' => 'Disable Dashboard Updates',
                'desc'  => 'Sets <code>DISALLOW_FILE_MODS</code> to block plugin, theme, and core updates from the dashboard. For sites maintained manually via WP-CLI or FTP.',
                'warn'  => '<i class="fa-solid fa-triangle-exclamation"></i> Also disables <strong>automatic security patches</strong>. Only enable on manually-maintained sites.',
            ],
            'disable_php_execution' => [
                'icon'  => 'fa-shield-halved',
                'ic'    => 'ic-green',
                'label' => 'Block PHP in Uploads Folder',
                'desc'  => 'Writes <code>&lt;Files *.php&gt; Deny from all&lt;/Files&gt;</code> into <code>wp-content/uploads/.htaccess</code>. Uploaded malware cannot execute even if it bypasses other defences.',
                'warn'  => '',
            ],
            'disable_directory_browsing' => [
                'icon'  => 'fa-folder-open',
                'ic'    => 'ic-orange',
                'label' => 'Disable Directory Browsing',
                'desc'  => 'Adds <code>Options -Indexes</code> to root <code>.htaccess</code>. Visitors cannot list folder contents when no index file exists.',
                'warn'  => '',
            ],
            'protect_wpconfig' => [
                'icon'  => 'fa-file-shield',
                'ic'    => 'ic-red',
                'label' => 'Protect wp-config.php',
                'desc'  => 'Adds <code>&lt;Files wp-config.php&gt; Deny from all&lt;/Files&gt;</code> to root <code>.htaccess</code>. Blocks direct HTTP access to your database credentials file.',
                'warn'  => '',
            ],
            'login_limit' => [
                'icon'      => 'fa-shield-virus',
                'ic'        => 'ic-purple',
                'label'     => 'Brute Force Login Protection',
                'desc'      => 'Locks an IP address out for 30 minutes after too many failed login attempts. Configurable threshold (3–20). Uses WordPress transients — no extra database tables. Cloudflare and proxy aware.',
                'warn'      => '',
                'has_count' => true,
            ],
            'generic_login_errors' => [
                'icon'  => 'fa-message',
                'ic'    => 'ic-blue',
                'label' => 'Generic Login Error Messages',
                'desc'  => 'Replaces WordPress\'s specific "wrong password" or "unknown username" messages with a single neutral message — prevents username confirmation via error text.',
                'warn'  => '',
            ],
            'disable_login_hints' => [
                'icon'  => 'fa-comment-dots',
                'ic'    => 'ic-slate',
                'label' => 'Disable Login Hints',
                'desc'  => 'Removes all contextual hints from login failure responses. Complements Generic Login Errors for a fully opaque login endpoint.',
                'warn'  => '',
            ],
            'block_user_enumeration' => [
                'icon'  => 'fa-user-slash',
                'ic'    => 'ic-indigo',
                'label' => 'Block User Enumeration',
                'desc'  => 'Redirects <code>?author=N</code> URL scans to the homepage (301) and removes <code>/wp-json/wp/v2/users</code> for unauthenticated requests.',
                'warn'  => '',
            ],
            'security_headers' => [
                'icon'  => 'fa-shield-virus',
                'ic'    => 'ic-teal',
                'label' => 'Core Security Headers (HSTS, CSP, Permissions-Policy)',
                'desc'  => 'Sends <code>Strict-Transport-Security</code>, a base <code>Content-Security-Policy</code>, and <code>Permissions-Policy</code> to restrict geolocation, microphone, and camera APIs.',
                'warn'  => '<i class="fa-solid fa-triangle-exclamation"></i> Test <strong>CSP</strong> on a staging site first — it may block inline scripts or third-party embeds.',
            ],
            'clickjacking_protection' => [
                'icon'  => 'fa-clone',
                'ic'    => 'ic-blue',
                'label' => 'Clickjacking Protection (X-Frame-Options)',
                'desc'  => 'Sends <code>X-Frame-Options: SAMEORIGIN</code> — prevents your site from being loaded inside an iframe on another domain.',
                'warn'  => '',
            ],
            'content_type_nosniff' => [
                'icon'  => 'fa-bug-slash',
                'ic'    => 'ic-green',
                'label' => 'MIME Sniffing &amp; XSS Protection',
                'desc'  => 'Sends <code>X-Content-Type-Options: nosniff</code> and <code>X-XSS-Protection: 1; mode=block</code> to stop browsers from guessing content types and executing reflected XSS.',
                'warn'  => '',
            ],
            'referrer_policy' => [
                'icon'  => 'fa-link-slash',
                'ic'    => 'ic-slate',
                'label' => 'Referrer Policy',
                'desc'  => 'Sends <code>Referrer-Policy: strict-origin-when-cross-origin</code> — limits how much URL information is passed to external sites when users follow links.',
                'warn'  => '',
            ],
            'disable_rest_api_for_guests' => [
                'icon'  => 'fa-lock',
                'ic'    => 'ic-indigo',
                'label' => 'Restrict Full REST API to Logged-In Users',
                'desc'  => 'Returns <code>401 Unauthorized</code> to all unauthenticated REST API requests. Prevents bulk data scraping through the API.',
                'warn'  => '<i class="fa-solid fa-triangle-exclamation"></i> May break features that rely on unauthenticated REST calls (e.g. some contact form plugins, headless themes).',
            ],
            'block_rest_users_endpoint' => [
                'icon'  => 'fa-users-slash',
                'ic'    => 'ic-red',
                'label' => 'Block REST API Users Endpoint',
                'desc'  => 'Removes <code>/wp-json/wp/v2/users</code> entirely — the most common REST-based username enumeration vector — without locking down the full API.',
                'warn'  => '',
            ],
            'disable_rss' => [
                'icon'  => 'fa-rss',
                'ic'    => 'ic-orange',
                'label' => 'Disable RSS &amp; Atom Feeds',
                'desc'  => 'Redirects all feed URLs to the homepage and removes feed <code>&lt;link&gt;</code> tags from <code>&lt;head&gt;</code>.',
                'warn'  => '',
            ],
            'remove_wp_embed' => [
                'icon'  => 'fa-code',
                'ic'    => 'ic-blue',
                'label' => 'Remove WP Embed Script',
                'desc'  => 'Dequeues <code>wp-embed.min.js</code> from every page load. Safe to enable if you do not use oEmbed blocks.',
                'warn'  => '',
            ],
            'remove_shortlink' => [
                'icon'  => 'fa-link',
                'ic'    => 'ic-slate',
                'label' => 'Remove Shortlink Tag',
                'desc'  => 'Removes <code>&lt;link rel="shortlink"&gt;</code> from <code>&lt;head&gt;</code> and the <code>Link</code> HTTP response header.',
                'warn'  => '',
            ],
            'disable_self_pingbacks' => [
                'icon'  => 'fa-bell-slash',
                'ic'    => 'ic-teal',
                'label' => 'Disable Self-Pingbacks',
                'desc'  => 'Prevents WordPress from sending pingback notifications to its own posts when you link internally. Eliminates unnecessary database writes.',
                'warn'  => '',
            ],
        ];
    }
}
