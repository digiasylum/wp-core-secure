<?php
/**
 * Plugin Name: WP Core Secure
 * Plugin URI:  https://www.digiasylum.com/
 * Description: Hardens your WordPress security — HTTP headers, brute force protection, user enumeration blocking, login hardening, and more. Zero telemetry.
 * Version:     2.2.0
 * Author:      Umesh Kumar Sahai
 * Author URI:  https://www.linkedin.com/in/umeshkumarsahai/
 * License:     GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires PHP: 7.4
 * Requires at least: 5.0
 * Tested up to: 6.8
 * Text Domain: wp-core-secure
 * Domain Path: /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ── Plugin-wide constants ─────────────────────────────────────────────────────
define( 'WPCS_VERSION',  '2.2.0' );
define( 'WPCS_FILE',     __FILE__ );
define( 'WPCS_DIR',      plugin_dir_path( __FILE__ ) );
define( 'WPCS_URL',      plugin_dir_url( __FILE__ ) );
define( 'WPCS_BASENAME', plugin_basename( __FILE__ ) );

// ── Autoload all classes ───────────────────────────────────────────────────────
require_once WPCS_DIR . 'includes/class-constants.php';
require_once WPCS_DIR . 'includes/class-htaccess.php';
require_once WPCS_DIR . 'includes/class-security.php';
require_once WPCS_DIR . 'includes/class-login.php';
require_once WPCS_DIR . 'includes/class-headers.php';
require_once WPCS_DIR . 'includes/class-api.php';
require_once WPCS_DIR . 'admin/class-admin.php';
require_once WPCS_DIR . 'admin/class-settings.php';

// ── Boot the plugin ───────────────────────────────────────────────────────────
function wpcs_boot() {
    $options = (array) get_option( WPCS_Constants::OPTION_KEY, [] );

    // Admin layer (menu, page, enqueue)
    ( new WPCS_Admin() )->boot();

    // Settings registration + sanitization
    ( new WPCS_Settings() )->boot();

    // Security feature modules
    ( new WPCS_Security( $options ) )->boot();
    ( new WPCS_Login(    $options ) )->boot();
    ( new WPCS_Headers(  $options ) )->boot();
    ( new WPCS_API(      $options ) )->boot();
    ( new WPCS_Htaccess( $options ) )->boot();
}
add_action( 'plugins_loaded', 'wpcs_boot' );

// ── Activation hook ───────────────────────────────────────────────────────────
register_activation_hook( WPCS_FILE, function () {
    $options = (array) get_option( WPCS_Constants::OPTION_KEY, [] );
    if ( ! empty( $options ) ) {
        ( new WPCS_Htaccess( $options ) )->write_all();
    }
} );

// ── Deactivation hook — clean all .htaccess blocks ───────────────────────────
register_deactivation_hook( WPCS_FILE, function () {
    ( new WPCS_Htaccess( [] ) )->remove_all();
} );
