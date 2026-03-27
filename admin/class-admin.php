<?php
/**
 * WPCS_Admin
 *
 * Handles everything visible in the WordPress admin:
 *  - Registering the top-level menu page
 *  - Enqueueing MDB CSS/JS and Font Awesome only on our page
 *  - Adding the "Settings" quick link on the Plugins list screen
 *
 * The actual HTML for the settings page lives in:
 *  admin/views/settings-page.php
 *
 * @package WPCoreSecure
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPCS_Admin {

    /**
     * Register all admin hooks.
     */
    public function boot() {
        add_action( 'admin_menu',            [ $this, 'register_menu'    ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets'   ] );
        add_filter(
            'plugin_action_links_' . WPCS_BASENAME,
            [ $this, 'add_settings_link' ]
        );
    }

    // ── Menu ──────────────────────────────────────────────────────────────────

    /**
     * Register the top-level "WP Core Secure" admin menu item.
     */
    public function register_menu() {
        add_menu_page(
            __( 'WP Core Secure', 'wp-core-secure' ),   // page <title>
            __( 'WP Core Secure', 'wp-core-secure' ),   // menu label
            'manage_options',                            // capability
            WPCS_Constants::MENU_SLUG,                   // menu slug
            [ $this, 'render_page' ],                    // callback
            'dashicons-shield-alt',                      // icon
            81                                           // position
        );
    }

    /**
     * Load and render the settings page view.
     * The view file handles all HTML output.
     */
    public function render_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        require_once WPCS_DIR . 'admin/views/settings-page.php';
    }

    // ── Assets ────────────────────────────────────────────────────────────────

    /**
     * Enqueue MDB 7, Font Awesome, and our own CSS/JS — only on our page.
     *
     * @param string $hook The current admin page hook suffix.
     */
    public function enqueue_assets( string $hook ) {
        if ( 'toplevel_page_' . WPCS_Constants::MENU_SLUG !== $hook ) {
            return;
        }

        // MDB 7 UI Kit
        wp_enqueue_style(
            'wpcs-mdb',
            'https://cdnjs.cloudflare.com/ajax/libs/mdb-ui-kit/7.3.2/mdb.min.css',
            [],
            '7.3.2'
        );
        wp_enqueue_script(
            'wpcs-mdb-js',
            'https://cdnjs.cloudflare.com/ajax/libs/mdb-ui-kit/7.3.2/mdb.umd.min.js',
            [],
            '7.3.2',
            true
        );

        // Font Awesome 6
        wp_enqueue_style(
            'wpcs-fa',
            'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css',
            [],
            '6.5.2'
        );

        // Plugin-specific admin styles
        wp_enqueue_style(
            'wpcs-admin',
            WPCS_URL . 'admin/css/admin.css',
            [ 'wpcs-mdb', 'wpcs-fa' ],
            WPCS_VERSION
        );

        // Plugin-specific admin JS
        wp_enqueue_script(
            'wpcs-admin-js',
            WPCS_URL . 'admin/js/admin.js',
            [ 'wpcs-mdb-js' ],
            WPCS_VERSION,
            true
        );
    }

    // ── Plugin list link ──────────────────────────────────────────────────────

    /**
     * Add a "Settings" quick-action link on the Plugins screen.
     *
     * @param  array $links Existing action links.
     * @return array
     */
    public function add_settings_link( array $links ): array {
        $url  = admin_url( 'admin.php?page=' . WPCS_Constants::MENU_SLUG );
        $link = '<a href="' . esc_url( $url ) . '">' . __( 'Settings', 'wp-core-secure' ) . '</a>';
        array_unshift( $links, $link );
        return $links;
    }
}
