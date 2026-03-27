<?php
/**
 * WPCS_Security
 *
 * Core WordPress hardening — filters and actions that tighten default
 * WordPress behaviour without touching .htaccess or HTTP headers.
 * Covers: XML-RPC, version hiding, file editing, feeds, embed, shortlink,
 * self-pingbacks, and DISALLOW_FILE_MODS.
 *
 * @package WPCoreSecure
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPCS_Security {

    /** @var array Plugin options */
    private $options;

    public function __construct( array $options ) {
        $this->options = $options;
    }

    /**
     * Register all hooks for enabled security features.
     * Runs on plugins_loaded via the main boot function.
     */
    public function boot() {
        add_action( 'init', [ $this, 'apply' ], 1 );
    }

    /**
     * Apply every enabled core hardening rule.
     * Hooked to `init` at priority 1 so it runs before themes and other plugins.
     */
    public function apply() {
        $o = $this->options;

        $this->maybe_disable_xmlrpc( $o );
        $this->maybe_hide_version( $o );
        $this->maybe_hide_footer( $o );
        $this->maybe_disable_file_editing( $o );
        $this->maybe_disable_updates( $o );
        $this->maybe_disable_rss( $o );
        $this->maybe_remove_embed( $o );
        $this->maybe_remove_shortlink( $o );
        $this->maybe_disable_self_pingbacks( $o );
    }

    // ── Feature implementations ───────────────────────────────────────────────

    private function maybe_disable_xmlrpc( array $o ) {
        if ( empty( $o['disable_xmlrpc'] ) ) return;

        add_filter( 'xmlrpc_enabled',  '__return_false' );
        add_filter( 'xmlrpc_methods',  '__return_empty_array' );
        remove_action( 'wp_head', 'rsd_link' );
        remove_action( 'wp_head', 'wlwmanifest_link' );
        remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
        remove_action( 'wp_head', 'wp_oembed_add_host_js' );
    }

    private function maybe_hide_version( array $o ) {
        if ( empty( $o['hide_version'] ) ) return;

        remove_action( 'wp_head', 'wp_generator' );
        add_filter( 'the_generator', '__return_empty_string' );

        // Strip ?ver= query string from all enqueued scripts and styles
        add_filter( 'script_loader_src', [ $this, 'strip_version_param' ] );
        add_filter( 'style_loader_src',  [ $this, 'strip_version_param' ] );
    }

    private function maybe_hide_footer( array $o ) {
        if ( empty( $o['hide_footer_message'] ) ) return;

        add_filter( 'admin_footer_text', '__return_empty_string' );
        add_filter( 'update_footer',     '__return_empty_string', 11 );
    }

    private function maybe_disable_file_editing( array $o ) {
        if ( empty( $o['disable_file_editing'] ) ) return;
        if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
            define( 'DISALLOW_FILE_EDIT', true );
        }
    }

    private function maybe_disable_updates( array $o ) {
        if ( empty( $o['disable_updates'] ) ) return;
        if ( ! defined( 'DISALLOW_FILE_MODS' ) ) {
            define( 'DISALLOW_FILE_MODS', true );
        }
    }

    private function maybe_disable_rss( array $o ) {
        if ( empty( $o['disable_rss'] ) ) return;

        remove_action( 'wp_head', 'feed_links',       2 );
        remove_action( 'wp_head', 'feed_links_extra', 3 );

        $redirect = static function () {
            wp_redirect( home_url() );
            exit;
        };
        foreach ( [ 'do_feed', 'do_feed_rdf', 'do_feed_rss', 'do_feed_rss2', 'do_feed_atom' ] as $hook ) {
            add_action( $hook, $redirect, 1 );
        }
    }

    private function maybe_remove_embed( array $o ) {
        if ( empty( $o['remove_wp_embed'] ) ) return;

        add_action( 'wp_enqueue_scripts', static function () {
            wp_dequeue_script( 'wp-embed' );
        } );
        remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
    }

    private function maybe_remove_shortlink( array $o ) {
        if ( empty( $o['remove_shortlink'] ) ) return;

        remove_action( 'wp_head',          'wp_shortlink_wp_head', 10 );
        remove_action( 'template_redirect', 'wp_shortlink_header',  11 );
    }

    private function maybe_disable_self_pingbacks( array $o ) {
        if ( empty( $o['disable_self_pingbacks'] ) ) return;

        add_action( 'pre_ping', [ $this, 'remove_self_pings' ] );
    }

    // ── Callbacks ─────────────────────────────────────────────────────────────

    /**
     * Remove ?ver= from a script or stylesheet URL.
     *
     * @param  string $src
     * @return string
     */
    public function strip_version_param( string $src ): string {
        if ( strpos( $src, 'ver=' ) !== false ) {
            $src = remove_query_arg( 'ver', $src );
        }
        return $src;
    }

    /**
     * Remove any links that point back to this site from the pingback list.
     *
     * @param array $links Passed by reference.
     */
    public function remove_self_pings( array &$links ) {
        $home = get_option( 'home' );
        foreach ( $links as $key => $link ) {
            if ( strpos( $link, $home ) === 0 ) {
                unset( $links[ $key ] );
            }
        }
    }
}
