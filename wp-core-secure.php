<?php
/**
 * Plugin Name: WP Core Secure
 * Plugin URI:  https://www.digiasylum.com/
 * Description: Hardens your WordPress security — HTTP headers, brute force protection, user enumeration blocking, login hardening, and more. Zero telemetry.
 * Version:     2.1.0
 * Author:      Umesh Kumar Sahai
 * Author URI:  https://www.linkedin.com/in/umeshkumarsahai/
 * License:     GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires PHP: 7.4
 * Requires at least: 5.0
 * Tested up to: 6.8
 * Text Domain: wp-core-secure
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPCoreSecure {

    const VERSION    = '2.1.0';
    const OPTION_KEY = 'wpcs_settings';
    const MENU_SLUG  = 'wpcs-settings';
    const TRANSIENT  = 'wpcs_login_attempts_';   // prefix; append IP hash

    private $options = [];

    // =========================================================================
    // BOOT
    // =========================================================================
    public function __construct() {
        $this->options = (array) get_option( self::OPTION_KEY, [] );

        add_action( 'admin_menu',            [ $this, 'add_settings_page' ] );
        add_action( 'admin_init',            [ $this, 'register_settings' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin_assets' ] );
        add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), [ $this, 'add_settings_link' ] );

        // Core security — priority 1, never nested
        add_action( 'init', [ $this, 'apply_security_settings' ], 1 );

        // .htaccess writes: only on save, never on every request
        add_action( 'update_option_' . self::OPTION_KEY, [ $this, 'on_option_save' ], 10, 2 );
        add_action( 'add_option_'    . self::OPTION_KEY, [ $this, 'on_option_add'  ], 10, 2 );

        register_activation_hook(   __FILE__, [ $this, 'on_activate'   ] );
        register_deactivation_hook( __FILE__, [ $this, 'on_deactivate' ] );
    }

    // =========================================================================
    // ACTIVATION / DEACTIVATION
    // =========================================================================
    public function on_activate() {
        // Trigger htaccess write with current saved options on activation
        $opts = (array) get_option( self::OPTION_KEY, [] );
        if ( ! empty( $opts ) ) {
            $this->write_all_htaccess( $opts );
        }
    }

    public function on_deactivate() {
        $this->remove_all_htaccess_blocks();
    }

    // =========================================================================
    // ADMIN MENU & ASSETS
    // =========================================================================
    public function add_settings_page() {
        add_menu_page(
            'WP Core Secure',
            'WP Core Secure',
            'manage_options',
            self::MENU_SLUG,
            [ $this, 'render_page' ],
            'dashicons-shield-alt',
            81
        );
    }

    public function add_settings_link( $links ) {
        array_unshift( $links, '<a href="' . esc_url( admin_url( 'admin.php?page=' . self::MENU_SLUG ) ) . '">Settings</a>' );
        return $links;
    }

    public function enqueue_admin_assets( $hook ) {
        if ( 'toplevel_page_' . self::MENU_SLUG !== $hook ) return;
        wp_enqueue_style(  'mdb-css', 'https://cdnjs.cloudflare.com/ajax/libs/mdb-ui-kit/7.3.2/mdb.min.css', [], '7.3.2' );
        wp_enqueue_script( 'mdb-js',  'https://cdnjs.cloudflare.com/ajax/libs/mdb-ui-kit/7.3.2/mdb.umd.min.js', [], '7.3.2', true );
    }

    // =========================================================================
    // SETTINGS REGISTRATION & SANITIZATION
    // =========================================================================
    public function register_settings() {
        register_setting( 'wpcs_group', self::OPTION_KEY, [ $this, 'sanitize' ] );
    }

    public function sanitize( $in ) {
        $out = [];
        foreach ( $this->all_feature_keys() as $key ) {
            $out[ $key ] = ! empty( $in[ $key ] ) ? 1 : 0;
        }
        // Login limit count — integer 3–20
        $out['login_limit_count'] = isset( $in['login_limit_count'] )
            ? max( 3, min( 20, (int) $in['login_limit_count'] ) ) : 5;
        return $out;
    }

    private function all_feature_keys() {
        return [
            // Group: Core Hardening
            'disable_xmlrpc',
            'hide_version',
            'hide_footer_message',
            'disable_file_editing',
            'disable_updates',
            // Group: File System
            'disable_php_execution',
            'disable_directory_browsing',
            'protect_wpconfig',
            // Group: Login Security
            'login_limit',
            'generic_login_errors',
            'disable_login_hints',
            'block_user_enumeration',
            // Group: HTTP Security Headers
            'security_headers',
            'clickjacking_protection',
            'content_type_nosniff',
            'referrer_policy',
            // Group: Access & API
            'disable_rest_api_for_guests',
            'block_rest_users_endpoint',
            'disable_rss',
            'remove_wp_embed',
            'remove_shortlink',
            'disable_self_pingbacks',
        ];
    }

    // =========================================================================
    // .HTACCESS MANAGEMENT — event-driven, never on page load
    // =========================================================================
    public function on_option_add( $option, $new ) { $this->write_all_htaccess( (array) $new ); }
    public function on_option_save( $old, $new )    { $this->write_all_htaccess( (array) $new ); }

    private function write_all_htaccess( array $o ) {
        // 1. XML-RPC block
        $this->htaccess_toggle(
            ABSPATH . '.htaccess',
            'xmlrpc-block',
            "<Files xmlrpc.php>\n    Order Deny,Allow\n    Deny from all\n</Files>",
            ! empty( $o['disable_xmlrpc'] )
        );

        // 2. Directory indexing
        $this->htaccess_toggle(
            ABSPATH . '.htaccess',
            'no-indexes',
            "Options -Indexes",
            ! empty( $o['disable_directory_browsing'] )
        );

        // 3. Protect wp-config.php
        $this->htaccess_toggle(
            ABSPATH . '.htaccess',
            'protect-wpconfig',
            "<Files wp-config.php>\n    Order Allow,Deny\n    Deny from all\n</Files>",
            ! empty( $o['protect_wpconfig'] )
        );

        // 4. PHP execution block in uploads
        $uploads = wp_upload_dir();
        $this->htaccess_toggle(
            trailingslashit( $uploads['basedir'] ) . '.htaccess',
            'no-php-uploads',
            "<Files *.php>\n    Order Deny,Allow\n    Deny from all\n</Files>",
            ! empty( $o['disable_php_execution'] )
        );
    }

    /**
     * Toggle a named block in an .htaccess file.
     * Uses BEGIN/END markers so blocks are idempotent and cleanly removable.
     */
    private function htaccess_toggle( $file, $id, $rules, $enable ) {
        $begin = "# BEGIN WP-Core-Secure: {$id}";
        $end   = "# END WP-Core-Secure: {$id}";
        $block = "{$begin}\n{$rules}\n{$end}";
        $dir   = dirname( $file );

        if ( $enable ) {
            if ( ! is_dir( $dir ) ) wp_mkdir_p( $dir );
            $existing = file_exists( $file ) ? file_get_contents( $file ) : '';
            if ( strpos( $existing, $begin ) !== false ) return; // already present
            file_put_contents( $file, "\n" . $block . "\n", FILE_APPEND | LOCK_EX );
        } else {
            if ( ! file_exists( $file ) ) return;
            $content = file_get_contents( $file );
            $pattern = '/\n?' . preg_quote( $begin, '/' ) . '.*?' . preg_quote( $end, '/' ) . '\n?/s';
            $cleaned = preg_replace( $pattern, '', $content );
            if ( $cleaned !== $content ) {
                file_put_contents( $file, $cleaned, LOCK_EX );
            }
        }
    }

    private function remove_all_htaccess_blocks() {
        $ids     = [ 'xmlrpc-block', 'no-indexes', 'protect-wpconfig' ];
        $root_ht = ABSPATH . '.htaccess';
        if ( file_exists( $root_ht ) ) {
            $c = file_get_contents( $root_ht );
            foreach ( $ids as $id ) {
                $begin = "# BEGIN WP-Core-Secure: {$id}";
                $end   = "# END WP-Core-Secure: {$id}";
                $c = preg_replace( '/\n?' . preg_quote( $begin, '/' ) . '.*?' . preg_quote( $end, '/' ) . '\n?/s', '', $c );
            }
            file_put_contents( $root_ht, $c, LOCK_EX );
        }
        $uploads = wp_upload_dir();
        $up_ht   = trailingslashit( $uploads['basedir'] ) . '.htaccess';
        if ( file_exists( $up_ht ) ) {
            $c     = file_get_contents( $up_ht );
            $begin = '# BEGIN WP-Core-Secure: no-php-uploads';
            $end   = '# END WP-Core-Secure: no-php-uploads';
            $c     = preg_replace( '/\n?' . preg_quote( $begin, '/' ) . '.*?' . preg_quote( $end, '/' ) . '\n?/s', '', $c );
            file_put_contents( $up_ht, $c, LOCK_EX );
        }
    }

    // =========================================================================
    // APPLY RUNTIME SECURITY  (fires on `init`, priority 1)
    // =========================================================================
    public function apply_security_settings() {
        $o = $this->options;

        // --- Core Hardening ---------------------------------------------------

        if ( ! empty( $o['disable_xmlrpc'] ) ) {
            add_filter( 'xmlrpc_enabled',  '__return_false' );
            add_filter( 'xmlrpc_methods',  '__return_empty_array' );
            remove_action( 'wp_head', 'rsd_link' );
            remove_action( 'wp_head', 'wlwmanifest_link' );
            remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
            remove_action( 'wp_head', 'wp_oembed_add_host_js' );
        }

        if ( ! empty( $o['hide_version'] ) ) {
            remove_action( 'wp_head', 'wp_generator' );
            add_filter( 'the_generator', '__return_empty_string' );
            // Strip ?ver= query strings from scripts/styles
            add_filter( 'script_loader_src', [ $this, 'strip_ver_param' ] );
            add_filter( 'style_loader_src',  [ $this, 'strip_ver_param' ] );
        }

        if ( ! empty( $o['hide_footer_message'] ) ) {
            add_filter( 'admin_footer_text', '__return_empty_string' );
            add_filter( 'update_footer',     '__return_empty_string', 11 );
        }

        if ( ! empty( $o['disable_file_editing'] ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
            define( 'DISALLOW_FILE_EDIT', true );
        }

        if ( ! empty( $o['disable_updates'] ) && ! defined( 'DISALLOW_FILE_MODS' ) ) {
            define( 'DISALLOW_FILE_MODS', true );
        }

        // --- Login Security ---------------------------------------------------

        if ( ! empty( $o['login_limit'] ) ) {
            add_action( 'wp_login_failed',  [ $this, 'record_failed_login' ] );
            add_filter( 'authenticate',     [ $this, 'check_login_limit' ], 30, 3 );
        }

        if ( ! empty( $o['generic_login_errors'] ) ) {
            add_filter( 'login_errors', static function() {
                return __( 'Incorrect username or password.', 'wp-core-secure' );
            } );
        }

        if ( ! empty( $o['disable_login_hints'] ) ) {
            add_filter( 'login_errors', static function() {
                return __( 'Login failed. Please try again.', 'wp-core-secure' );
            } );
        }

        if ( ! empty( $o['block_user_enumeration'] ) ) {
            // Block ?author=N scans
            add_action( 'template_redirect', [ $this, 'block_author_scan' ] );
            // Block /wp-json/wp/v2/users unauthenticated
            add_filter( 'rest_endpoints', [ $this, 'block_rest_users_unauth' ] );
        }

        // --- HTTP Security Headers --------------------------------------------

        if ( ! empty( $o['security_headers'] ) || ! empty( $o['clickjacking_protection'] ) || ! empty( $o['content_type_nosniff'] ) || ! empty( $o['referrer_policy'] ) ) {
            add_action( 'send_headers', [ $this, 'send_security_headers' ] );
        }

        // --- RSS / Feeds -------------------------------------------------------

        if ( ! empty( $o['disable_rss'] ) ) {
            remove_action( 'wp_head', 'feed_links',       2 );
            remove_action( 'wp_head', 'feed_links_extra', 3 );
            foreach ( [ 'do_feed', 'do_feed_rdf', 'do_feed_rss', 'do_feed_rss2', 'do_feed_atom' ] as $hook ) {
                add_action( $hook, static function() { wp_redirect( home_url() ); exit; }, 1 );
            }
        }

        // --- Misc Hardening ---------------------------------------------------

        if ( ! empty( $o['remove_wp_embed'] ) ) {
            add_action( 'wp_enqueue_scripts', static function() { wp_dequeue_script( 'wp-embed' ); } );
            remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
        }

        if ( ! empty( $o['remove_shortlink'] ) ) {
            remove_action( 'wp_head', 'wp_shortlink_wp_head', 10 );
            remove_action( 'template_redirect', 'wp_shortlink_header', 11 );
        }

        if ( ! empty( $o['disable_self_pingbacks'] ) ) {
            add_action( 'pre_ping', [ $this, 'disable_self_pingbacks' ] );
        }

        if ( ! empty( $o['disable_rest_api_for_guests'] ) ) {
            add_filter( 'rest_authentication_errors', static function( $r ) {
                if ( ! is_user_logged_in() ) {
                    return new WP_Error( 'rest_not_logged_in', __( 'REST API restricted.', 'wp-core-secure' ), [ 'status' => 401 ] );
                }
                return $r;
            } );
        }

        if ( ! empty( $o['block_rest_users_endpoint'] ) ) {
            add_filter( 'rest_endpoints', [ $this, 'block_users_endpoint' ] );
        }
    }

    // =========================================================================
    // SECURITY FEATURE IMPLEMENTATIONS
    // =========================================================================

    /** Strip ?ver= from enqueued asset URLs */
    public function strip_ver_param( $src ) {
        if ( strpos( $src, 'ver=' ) ) {
            $src = remove_query_arg( 'ver', $src );
        }
        return $src;
    }

    /** Record a failed login attempt via transient */
    public function record_failed_login( $username ) {
        $key   = self::TRANSIENT . substr( md5( $this->get_client_ip() ), 0, 16 );
        $count = (int) get_transient( $key );
        set_transient( $key, $count + 1, 30 * MINUTE_IN_SECONDS );
    }

    /** Block authentication if too many failures */
    public function check_login_limit( $user, $username, $password ) {
        if ( empty( $username ) ) return $user;
        $key   = self::TRANSIENT . substr( md5( $this->get_client_ip() ), 0, 16 );
        $count = (int) get_transient( $key );
        $limit = isset( $this->options['login_limit_count'] ) ? (int) $this->options['login_limit_count'] : 5;
        if ( $count >= $limit ) {
            return new WP_Error(
                'too_many_attempts',
                sprintf( __( 'Too many failed login attempts. Try again in 30 minutes.', 'wp-core-secure' ) )
            );
        }
        return $user;
    }

    /** Block author scan: ?author=1 → redirect to home */
    public function block_author_scan() {
        if ( isset( $_GET['author'] ) && ! is_admin() ) {
            wp_redirect( home_url(), 301 );
            exit;
        }
    }

    /** Remove /wp/v2/users endpoint for unauthenticated requests */
    public function block_rest_users_unauth( $endpoints ) {
        if ( ! is_user_logged_in() ) {
            unset( $endpoints['/wp/v2/users'] );
            unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
        }
        return $endpoints;
    }

    /** Remove /wp/v2/users regardless of auth (if block_rest_users_endpoint is on) */
    public function block_users_endpoint( $endpoints ) {
        unset( $endpoints['/wp/v2/users'] );
        unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
        return $endpoints;
    }

    /** Send security-related HTTP response headers */
    public function send_security_headers() {
        $o = $this->options;
        if ( ! empty( $o['security_headers'] ) ) {
            header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' );
            header( "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src * data:; font-src *;" );
            header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
        }
        if ( ! empty( $o['clickjacking_protection'] ) ) {
            header( 'X-Frame-Options: SAMEORIGIN' );
        }
        if ( ! empty( $o['content_type_nosniff'] ) ) {
            header( 'X-Content-Type-Options: nosniff' );
            header( 'X-XSS-Protection: 1; mode=block' );
        }
        if ( ! empty( $o['referrer_policy'] ) ) {
            header( 'Referrer-Policy: strict-origin-when-cross-origin' );
        }
    }

    /** Prevent self-pingbacks */
    public function disable_self_pingbacks( &$links ) {
        $home = get_option( 'home' );
        foreach ( $links as $l => $link ) {
            if ( strpos( $link, $home ) === 0 ) {
                unset( $links[ $l ] );
            }
        }
    }

    /** Get real client IP, proxy-aware */
    private function get_client_ip() {
        foreach ( [ 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR' ] as $k ) {
            if ( ! empty( $_SERVER[ $k ] ) ) {
                $ip = trim( explode( ',', $_SERVER[ $k ] )[0] );
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) return $ip;
            }
        }
        return '0.0.0.0';
    }

    // =========================================================================
    // SETTINGS PAGE HTML
    // =========================================================================
    public function render_page() {
        if ( ! current_user_can( 'manage_options' ) ) return;
        $o     = (array) get_option( self::OPTION_KEY, [] );
        $saved = ! empty( $_GET['settings-updated'] );
        $limit = isset( $o['login_limit_count'] ) ? (int) $o['login_limit_count'] : 5;
        ?>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" crossorigin="anonymous"/>
        <style>
        #wpcs{max-width:960px;margin:28px auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}

        /* ── Developer Card ─────────────────────────────── */
        .wpcs-dev-card{background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:20px 26px;margin-bottom:22px;display:flex;align-items:center;gap:18px;box-shadow:0 1px 6px rgba(0,0,0,.06)}
        .wpcs-dev-logo{width:54px;height:54px;border-radius:12px;background:linear-gradient(135deg,#1a1a2e,#e94560);display:flex;align-items:center;justify-content:center;flex-shrink:0}
        .wpcs-dev-logo i{font-size:26px;color:#fff}
        .wpcs-dev-info{flex:1}
        .wpcs-dev-info h3{font-size:15px;font-weight:700;color:#1a1a2e;margin:0 0 3px}
        .wpcs-dev-info p{font-size:12.5px;color:#6b7280;margin:0 0 6px}
        .wpcs-dev-links{display:flex;gap:10px;flex-wrap:wrap}
        .wpcs-dev-links a{font-size:12px;font-weight:600;color:#1565c0;text-decoration:none;display:flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;border:1px solid #c7d7f0;transition:all .2s}
        .wpcs-dev-links a:hover{background:#1565c0;color:#fff;border-color:#1565c0}
        .wpcs-dev-version{font-size:11px;background:#f3f4f6;color:#6b7280;padding:4px 12px;border-radius:20px;font-weight:600;white-space:nowrap}

        /* ── Hero Banner ────────────────────────────────── */
        .wpcs-hero{background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);border-radius:16px;padding:32px 36px;margin-bottom:22px;color:#fff;display:flex;align-items:center;gap:22px}
        .wpcs-hero-icon{font-size:52px;color:#e94560;flex-shrink:0}
        .wpcs-hero h1{font-size:26px;font-weight:800;margin:0 0 5px;color:#fff}
        .wpcs-hero p{margin:0;opacity:.72;font-size:13.5px;max-width:560px}
        .wpcs-badge{background:#e94560;color:#fff;font-size:11px;padding:2px 10px;border-radius:20px;font-weight:700;letter-spacing:.5px;vertical-align:middle;margin-left:8px}

        /* ── Stats Row ──────────────────────────────────── */
        .wpcs-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px}
        .wpcs-stat{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;text-align:center}
        .wpcs-stat .s-num{font-size:28px;font-weight:800;color:#1565c0}
        .wpcs-stat .s-label{font-size:11px;color:#9ca3af;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:3px}

        /* ── Section Label ──────────────────────────────── */
        .section-sep{display:flex;align-items:center;gap:12px;margin:26px 0 14px}
        .section-sep .sep-line{flex:1;height:1px;background:#e5e7eb}
        .section-sep .sep-label{font-size:11px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:#9ca3af;white-space:nowrap}

        /* ── Feature Card ───────────────────────────────── */
        .fc{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:18px 22px;margin-bottom:12px;display:flex;align-items:center;gap:16px;transition:box-shadow .2s,border-color .2s}
        .fc:hover{box-shadow:0 4px 18px rgba(0,0,0,.08);border-color:#c7d7f0}
        .fc.active{border-color:#bbdefb;background:#f7fbff}
        .fc-icon{width:44px;height:44px;border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:17px}
        .fc-body{flex:1;min-width:0}
        .fc-title{font-size:14.5px;font-weight:700;color:#111827;margin:0 0 3px;display:flex;align-items:center;gap:8px}
        .fc-desc{font-size:12.5px;color:#6b7280;line-height:1.6;margin:0}
        .fc-desc code{background:#f3f4f6;padding:1px 5px;border-radius:4px;font-size:11.5px;color:#374151}
        .fc-warn{font-size:12px;color:#92400e;background:#fffbeb;border:1px solid #fde68a;padding:5px 10px;border-radius:6px;margin-top:7px;display:flex;align-items:flex-start;gap:6px}
        .fc-extra{margin-top:10px}
        .fc-extra label{font-size:12px;color:#374151;font-weight:600}
        .fc-extra input[type=number]{width:80px;padding:4px 8px;border:1px solid #d1d5db;border-radius:6px;font-size:13px;margin-left:8px}

        /* ── Toggle Switch ──────────────────────────────── */
        .wpcs-sw{position:relative;display:inline-block;width:50px;height:27px;flex-shrink:0}
        .wpcs-sw input{opacity:0;width:0;height:0}
        .wpcs-slider{position:absolute;cursor:pointer;inset:0;background:#d1d5db;border-radius:27px;transition:.3s}
        .wpcs-slider:before{content:"";position:absolute;width:19px;height:19px;left:4px;bottom:4px;background:#fff;border-radius:50%;transition:.3s;box-shadow:0 1px 4px rgba(0,0,0,.2)}
        .wpcs-sw input:checked+.wpcs-slider{background:#1565c0}
        .wpcs-sw input:checked+.wpcs-slider:before{transform:translateX(23px)}

        /* ── Notice / Actions ───────────────────────────── */
        .wpcs-notice{border-radius:10px;padding:13px 18px;margin-bottom:18px;font-size:13.5px;display:flex;align-items:center;gap:10px}
        .wpcs-notice.ok{background:#ecfdf5;border:1px solid #6ee7b7;color:#065f46}
        .wpcs-actions{display:flex;justify-content:flex-end;margin-top:10px}
        .wpcs-save{background:#e94560;color:#fff;border:none;padding:11px 34px;border-radius:8px;font-size:14.5px;font-weight:700;cursor:pointer;transition:background .2s;display:flex;align-items:center;gap:9px}
        .wpcs-save:hover{background:#c73652}

        /* Icon color helpers */
        .ic-red{background:#fef2f2;color:#dc2626}
        .ic-blue{background:#eff6ff;color:#1d4ed8}
        .ic-green{background:#f0fdf4;color:#16a34a}
        .ic-orange{background:#fff7ed;color:#ea580c}
        .ic-purple{background:#faf5ff;color:#7c3aed}
        .ic-teal{background:#f0fdfa;color:#0d9488}
        .ic-indigo{background:#eef2ff;color:#4338ca}
        .ic-slate{background:#f8fafc;color:#475569}
        </style>

        <div id="wpcs">

        <!-- ── Developer Card ───────────────────────────── -->
        <div class="wpcs-dev-card">
            <div class="wpcs-dev-logo"><i class="fa-solid fa-d"></i></div>
            <div class="wpcs-dev-info">
                <h3>Developed by Digi Asylum &amp; Umesh Kumar Sahai</h3>
                <p>A lightweight WordPress hardening plugin — zero telemetry, no subscriptions, just security.</p>
                <div class="wpcs-dev-links">
                    <a href="https://digiasylum.com" target="_blank" rel="noopener">
                        <i class="fa-solid fa-globe"></i> digiasylum.com
                    </a>
                    <a href="https://www.linkedin.com/in/umeshkumarsahai/" target="_blank" rel="noopener">
                        <i class="fa-brands fa-linkedin"></i> Umesh Kumar Sahai
                    </a>
                    <a href="mailto:connect@digiasylum.com">
                        <i class="fa-solid fa-envelope"></i> Support
                    </a>
                </div>
            </div>
            <div class="wpcs-dev-version">v<?php echo esc_html( self::VERSION ); ?></div>
        </div>

        <!-- ── Hero ─────────────────────────────────────── -->
        <div class="wpcs-hero">
            <div class="wpcs-hero-icon"><i class="fa-solid fa-shield-halved"></i></div>
            <div>
                <h1>WP Core Secure <span class="wpcs-badge">v<?php echo esc_html( self::VERSION ); ?></span></h1>
                <p>Multi-layer WordPress hardening — brute force protection, HTTP security headers, login security, user enumeration blocking, and more. No cloud, no calls home.</p>
            </div>
        </div>

        <!-- ── Stats ────────────────────────────────────── -->
        <?php
        $active = 0;
        foreach ( $this->all_feature_keys() as $k ) {
            if ( ! empty( $o[ $k ] ) ) $active++;
        }
        $groups = 5; $total = count( $this->all_feature_keys() );
        ?>
        <div class="wpcs-stats">
            <div class="wpcs-stat"><div class="s-num"><?php echo $active; ?></div><div class="s-label">Active Rules</div></div>
            <div class="wpcs-stat"><div class="s-num"><?php echo $total; ?></div><div class="s-label">Total Features</div></div>
            <div class="wpcs-stat"><div class="s-num"><?php echo $groups; ?></div><div class="s-label">Security Groups</div></div>
            <div class="wpcs-stat"><div class="s-num">0</div><div class="s-label">External Calls</div></div>
        </div>

        <?php if ( $saved ) : ?>
        <div class="wpcs-notice ok">
            <i class="fa-solid fa-circle-check" style="font-size:17px"></i>
            <strong>Settings saved.</strong>&nbsp; Security configuration updated successfully.
        </div>
        <?php endif; ?>

        <form method="post" action="options.php">
            <?php settings_fields( 'wpcs_group' ); ?>

            <?php
            $sections = [
                [
                    'label' => 'Core Hardening',
                    'icon'  => 'fa-screwdriver-wrench',
                    'features' => [
                        'disable_xmlrpc' => [
                            'icon'  => 'fa-plug-circle-xmark', 'ic' => 'ic-red',
                            'label' => 'Disable XML-RPC',
                            'desc'  => 'Blocks the <code>xmlrpc.php</code> endpoint. Prevents brute-force amplification and DDoS pingback attacks. Removes RSD &amp; WLW link tags from <code>&lt;head&gt;</code>.',
                            'warn'  => '',
                        ],
                        'hide_version' => [
                            'icon'  => 'fa-eye-slash', 'ic' => 'ic-blue',
                            'label' => 'Hide WordPress Version',
                            'desc'  => 'Strips the <code>wp_generator</code> meta tag, removes version from RSS feeds, and strips <code>?ver=</code> from enqueued script/style URLs.',
                            'warn'  => '',
                        ],
                        'hide_footer_message' => [
                            'icon'  => 'fa-comment-slash', 'ic' => 'ic-slate',
                            'label' => 'Remove Admin Footer Text',
                            'desc'  => 'Clears the "Thank you for creating with WordPress" and WP version string from the admin footer — minor fingerprinting reduction.',
                            'warn'  => '',
                        ],
                        'disable_file_editing' => [
                            'icon'  => 'fa-file-pen', 'ic' => 'ic-orange',
                            'label' => 'Disable Theme &amp; Plugin Editor',
                            'desc'  => 'Sets <code>DISALLOW_FILE_EDIT</code>. Removes the code editor from the admin. If an admin account is compromised, attackers can\'t inject code via the dashboard.',
                            'warn'  => '',
                        ],
                        'disable_updates' => [
                            'icon'  => 'fa-ban', 'ic' => 'ic-red',
                            'label' => 'Disable Dashboard Updates',
                            'desc'  => 'Sets <code>DISALLOW_FILE_MODS</code> to block plugin, theme, and core updates from the dashboard. For sites updated manually via WP-CLI or FTP.',
                            'warn'  => '<i class="fa-solid fa-triangle-exclamation"></i> Also disables <strong>automatic security patches</strong>. Only enable on manually-maintained sites.',
                        ],
                    ],
                ],
                [
                    'label' => 'File System Protection',
                    'icon'  => 'fa-folder-tree',
                    'features' => [
                        'disable_php_execution' => [
                            'icon'  => 'fa-shield-halved', 'ic' => 'ic-green',
                            'label' => 'Block PHP in Uploads Folder',
                            'desc'  => 'Writes <code>&lt;Files *.php&gt; Deny from all&lt;/Files&gt;</code> into <code>wp-content/uploads/.htaccess</code>. Even if malware is uploaded, it cannot execute.',
                            'warn'  => '',
                        ],
                        'disable_directory_browsing' => [
                            'icon'  => 'fa-folder-open', 'ic' => 'ic-orange',
                            'label' => 'Disable Directory Browsing',
                            'desc'  => 'Adds <code>Options -Indexes</code> to root <code>.htaccess</code>. Prevents visitors from listing folder contents when no index file exists.',
                            'warn'  => '',
                        ],
                        'protect_wpconfig' => [
                            'icon'  => 'fa-file-shield', 'ic' => 'ic-red',
                            'label' => 'Protect wp-config.php',
                            'desc'  => 'Adds a <code>&lt;Files wp-config.php&gt; Deny from all&lt;/Files&gt;</code> block to <code>.htaccess</code> — blocks direct HTTP access to your database credentials file.',
                            'warn'  => '',
                        ],
                    ],
                ],
                [
                    'label' => 'Login Security',
                    'icon'  => 'fa-lock',
                    'features' => [
                        'login_limit' => [
                            'icon'     => 'fa-shield-virus', 'ic' => 'ic-purple',
                            'label'    => 'Brute Force Login Protection',
                            'desc'     => 'Locks out an IP address for 30 minutes after too many failed login attempts. Uses WordPress transients — no extra database tables.',
                            'warn'     => '',
                            'has_count' => true,
                        ],
                        'generic_login_errors' => [
                            'icon'  => 'fa-message', 'ic' => 'ic-blue',
                            'label' => 'Generic Login Error Messages',
                            'desc'  => 'Replaces WordPress\'s helpful "wrong password" / "unknown user" messages with a single generic message so attackers can\'t confirm valid usernames.',
                            'warn'  => '',
                        ],
                        'block_user_enumeration' => [
                            'icon'  => 'fa-user-slash', 'ic' => 'ic-indigo',
                            'label' => 'Block User Enumeration',
                            'desc'  => 'Redirects <code>?author=1</code> scans to homepage and removes the <code>/wp-json/wp/v2/users</code> REST endpoint for unauthenticated visitors.',
                            'warn'  => '',
                        ],
                    ],
                ],
                [
                    'label' => 'HTTP Security Headers',
                    'icon'  => 'fa-heading',
                    'features' => [
                        'security_headers' => [
                            'icon'  => 'fa-shield-virus', 'ic' => 'ic-teal',
                            'label' => 'Core Security Headers (HSTS, CSP, Permissions-Policy)',
                            'desc'  => 'Sends <code>Strict-Transport-Security</code>, a base <code>Content-Security-Policy</code>, and <code>Permissions-Policy</code> to restrict geolocation, mic &amp; camera APIs.',
                            'warn'  => '<i class="fa-solid fa-triangle-exclamation"></i> Test the <strong>CSP header</strong> on a staging site first — it may block inline scripts or third-party embeds.',
                        ],
                        'clickjacking_protection' => [
                            'icon'  => 'fa-clone', 'ic' => 'ic-blue',
                            'label' => 'Clickjacking Protection (X-Frame-Options)',
                            'desc'  => 'Sends <code>X-Frame-Options: SAMEORIGIN</code> — prevents your site from being embedded in an iframe on another domain (protects against clickjacking attacks).',
                            'warn'  => '',
                        ],
                        'content_type_nosniff' => [
                            'icon'  => 'fa-bug-slash', 'ic' => 'ic-green',
                            'label' => 'MIME Sniffing &amp; XSS Protection',
                            'desc'  => 'Sends <code>X-Content-Type-Options: nosniff</code> and <code>X-XSS-Protection: 1; mode=block</code> to prevent browsers from guessing content types and from executing reflected XSS.',
                            'warn'  => '',
                        ],
                        'referrer_policy' => [
                            'icon'  => 'fa-link-slash', 'ic' => 'ic-slate',
                            'label' => 'Referrer Policy',
                            'desc'  => 'Sends <code>Referrer-Policy: strict-origin-when-cross-origin</code> — controls how much URL info is sent to external sites when users click links, protecting URL-embedded tokens.',
                            'warn'  => '',
                        ],
                    ],
                ],
                [
                    'label' => 'Access &amp; API Control',
                    'icon'  => 'fa-sliders',
                    'features' => [
                        'disable_rest_api_for_guests' => [
                            'icon'  => 'fa-lock', 'ic' => 'ic-indigo',
                            'label' => 'Restrict Full REST API to Logged-In Users',
                            'desc'  => 'Returns <code>401 Unauthorized</code> to all unauthenticated REST API requests. Prevents bulk data scraping via the API.',
                            'warn'  => '<i class="fa-solid fa-triangle-exclamation"></i> May break public-facing features that rely on unauthenticated REST calls (e.g. some contact form plugins, headless themes).',
                        ],
                        'block_rest_users_endpoint' => [
                            'icon'  => 'fa-users-slash', 'ic' => 'ic-red',
                            'label' => 'Block REST API Users Endpoint',
                            'desc'  => 'Removes <code>/wp-json/wp/v2/users</code> entirely. Stops the single biggest user-enumeration vector in the REST API without locking down the whole API.',
                            'warn'  => '',
                        ],
                        'disable_rss' => [
                            'icon'  => 'fa-rss', 'ic' => 'ic-orange',
                            'label' => 'Disable RSS / Atom Feeds',
                            'desc'  => 'Redirects all feed URLs to homepage and removes feed <code>&lt;link&gt;</code> tags from <code>&lt;head&gt;</code>. Useful for apps/tools that don\'t need public feeds.',
                            'warn'  => '',
                        ],
                        'remove_wp_embed' => [
                            'icon'  => 'fa-code', 'ic' => 'ic-blue',
                            'label' => 'Remove WP Embed Script',
                            'desc'  => 'Dequeues <code>wp-embed.min.js</code> — a script loaded on every page. Safe to enable if you don\'t use oEmbed block embeds.',
                            'warn'  => '',
                        ],
                        'remove_shortlink' => [
                            'icon'  => 'fa-link', 'ic' => 'ic-slate',
                            'label' => 'Remove Shortlink Tag',
                            'desc'  => 'Removes the <code>&lt;link rel="shortlink"&gt;</code> from <code>&lt;head&gt;</code> and the <code>Link</code> HTTP response header. Minor cleanup &amp; fingerprinting reduction.',
                            'warn'  => '',
                        ],
                        'disable_self_pingbacks' => [
                            'icon'  => 'fa-bell-slash', 'ic' => 'ic-teal',
                            'label' => 'Disable Self-Pingbacks',
                            'desc'  => 'Prevents WordPress from sending pingbacks to its own posts when you link internally. Eliminates unnecessary database writes &amp; self-generated noise in comments.',
                            'warn'  => '',
                        ],
                    ],
                ],
            ];

            foreach ( $sections as $section ) :
            ?>
            <div class="section-sep">
                <span class="sep-line"></span>
                <span class="sep-label"><i class="fa-solid <?php echo esc_attr( $section['icon'] ); ?>" style="margin-right:5px"></i><?php echo wp_kses_post( $section['label'] ); ?></span>
                <span class="sep-line"></span>
            </div>

            <?php foreach ( $section['features'] as $key => $f ) :
                $checked   = ! empty( $o[ $key ] );
                $has_count = ! empty( $f['has_count'] );
            ?>
            <div class="fc<?php echo $checked ? ' active' : ''; ?>">
                <div class="fc-icon <?php echo esc_attr( $f['ic'] ); ?>">
                    <i class="fa-solid <?php echo esc_attr( $f['icon'] ); ?>"></i>
                </div>
                <div class="fc-body">
                    <div class="fc-title">
                        <?php echo wp_kses_post( $f['label'] ); ?>
                        <?php if ( $checked ) : ?><span style="font-size:10px;background:#dcfce7;color:#15803d;padding:2px 8px;border-radius:10px;font-weight:600">ACTIVE</span><?php endif; ?>
                    </div>
                    <div class="fc-desc"><?php echo wp_kses_post( $f['desc'] ); ?></div>
                    <?php if ( ! empty( $f['warn'] ) ) : ?>
                    <div class="fc-warn"><?php echo wp_kses_post( $f['warn'] ); ?></div>
                    <?php endif; ?>
                    <?php if ( $has_count ) : ?>
                    <div class="fc-extra">
                        <label>Max attempts before lockout:
                            <input type="number" name="wpcs_settings[login_limit_count]" value="<?php echo esc_attr( $limit ); ?>" min="3" max="20">
                        </label>
                    </div>
                    <?php endif; ?>
                </div>
                <label class="wpcs-sw" title="Toggle <?php echo esc_attr( strip_tags( $f['label'] ) ); ?>">
                    <input type="checkbox"
                           name="wpcs_settings[<?php echo esc_attr( $key ); ?>]"
                           value="1"
                           <?php checked( $checked ); ?>>
                    <span class="wpcs-slider"></span>
                </label>
            </div>
            <?php endforeach; ?>
            <?php endforeach; ?>

            <div class="wpcs-actions">
                <button type="submit" class="wpcs-save">
                    <i class="fa-solid fa-floppy-disk"></i> Save Settings
                </button>
            </div>

        </form>

        <!-- live ACTIVE badge toggle without page reload -->
        <script>
        document.querySelectorAll('.wpcs-sw input').forEach(function(cb){
            cb.addEventListener('change',function(){
                var card=this.closest('.fc');
                var badge=card.querySelector('.fc-title span[style]');
                if(this.checked){
                    card.classList.add('active');
                    if(!badge){
                        var t=card.querySelector('.fc-title');
                        var s=document.createElement('span');
                        s.style.cssText='font-size:10px;background:#dcfce7;color:#15803d;padding:2px 8px;border-radius:10px;font-weight:600';
                        s.textContent='ACTIVE';
                        t.appendChild(s);
                    }
                }else{
                    card.classList.remove('active');
                    if(badge)badge.remove();
                }
            });
        });
        </script>

        </div>
        <?php
    }
}

new WPCoreSecure();
