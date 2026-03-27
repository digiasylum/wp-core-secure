<?php
/**
 * WPCS_Login
 *
 * Login security features:
 *  - Brute force IP lockout (transient-based, no extra DB tables)
 *  - Generic / opaque login error messages
 *  - Block user enumeration via ?author= scan and REST endpoint
 *
 * @package WPCoreSecure
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPCS_Login {

    /** @var array Plugin options */
    private $options;

    public function __construct( array $options ) {
        $this->options = $options;
    }

    /**
     * Register login-related hooks.
     */
    public function boot() {
        add_action( 'init', [ $this, 'apply' ], 1 );
    }

    /**
     * Apply enabled login security rules.
     */
    public function apply() {
        $o = $this->options;

        $this->maybe_brute_force_protection( $o );
        $this->maybe_generic_errors( $o );
        $this->maybe_block_enumeration( $o );
    }

    // ── Feature implementations ───────────────────────────────────────────────

    private function maybe_brute_force_protection( array $o ) {
        if ( empty( $o['login_limit'] ) ) return;

        add_action( 'wp_login_failed', [ $this, 'record_failure'   ] );
        add_filter( 'authenticate',    [ $this, 'check_lockout'    ], 30, 3 );
    }

    private function maybe_generic_errors( array $o ) {
        if ( empty( $o['generic_login_errors'] ) && empty( $o['disable_login_hints'] ) ) return;

        add_filter( 'login_errors', static function () {
            return __( 'Login failed. Please check your credentials and try again.', 'wp-core-secure' );
        } );
    }

    private function maybe_block_enumeration( array $o ) {
        if ( empty( $o['block_user_enumeration'] ) ) return;

        // Block ?author=N URL scans
        add_action( 'template_redirect', [ $this, 'block_author_scan' ] );

        // Block /wp-json/wp/v2/users for unauthenticated requests
        add_filter( 'rest_endpoints', [ $this, 'remove_users_endpoint_for_guests' ] );
    }

    // ── Brute force callbacks ─────────────────────────────────────────────────

    /**
     * Increment the failure counter for this IP on every failed login.
     *
     * @param string $username The username that was attempted.
     */
    public function record_failure( string $username ) {
        $key   = $this->transient_key();
        $count = (int) get_transient( $key );
        set_transient( $key, $count + 1, WPCS_Constants::LOCKOUT_DURATION );
    }

    /**
     * Block authentication when the failure threshold is exceeded.
     * Hooked to `authenticate` at priority 30 (after WP's own checks).
     *
     * @param  WP_User|WP_Error|null $user
     * @param  string                $username
     * @param  string                $password
     * @return WP_User|WP_Error|null
     */
    public function check_lockout( $user, string $username, string $password ) {
        if ( empty( $username ) ) {
            return $user;
        }

        $count = (int) get_transient( $this->transient_key() );
        $limit = $this->attempt_limit();

        if ( $count >= $limit ) {
            return new WP_Error(
                'wpcs_too_many_attempts',
                __( 'Too many failed login attempts. Please try again in 30 minutes.', 'wp-core-secure' )
            );
        }

        return $user;
    }

    // ── Enumeration callbacks ─────────────────────────────────────────────────

    /**
     * Redirect ?author=N requests to the homepage.
     */
    public function block_author_scan() {
        if ( isset( $_GET['author'] ) && ! is_admin() ) {
            wp_redirect( home_url(), 301 );
            exit;
        }
    }

    /**
     * Remove /wp/v2/users and /wp/v2/users/{id} for unauthenticated visitors.
     *
     * @param  array $endpoints All registered REST endpoints.
     * @return array
     */
    public function remove_users_endpoint_for_guests( array $endpoints ): array {
        if ( ! is_user_logged_in() ) {
            unset( $endpoints['/wp/v2/users'] );
            unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
        }
        return $endpoints;
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Build the transient key for the current client IP.
     * Hashed so long IPs (IPv6) don't exceed the 172-char transient key limit.
     *
     * @return string
     */
    private function transient_key(): string {
        return WPCS_Constants::TRANSIENT_PREFIX . substr( md5( $this->client_ip() ), 0, 16 );
    }

    /**
     * Return the configured attempt limit (default 5, clamped 3–20).
     *
     * @return int
     */
    private function attempt_limit(): int {
        $limit = isset( $this->options['login_limit_count'] )
            ? (int) $this->options['login_limit_count']
            : 5;
        return max( 3, min( 20, $limit ) );
    }

    /**
     * Resolve the real client IP, checking Cloudflare and common proxy headers
     * before falling back to REMOTE_ADDR.
     *
     * @return string A valid IP address string, or '0.0.0.0' as a fallback.
     */
    private function client_ip(): string {
        $headers = [
            'HTTP_CF_CONNECTING_IP',  // Cloudflare
            'HTTP_X_FORWARDED_FOR',   // Load balancers / proxies
            'HTTP_X_REAL_IP',         // Nginx proxy
            'REMOTE_ADDR',            // Direct connection
        ];

        foreach ( $headers as $header ) {
            if ( ! empty( $_SERVER[ $header ] ) ) {
                // X-Forwarded-For can be a comma-separated list; take the first
                $ip = trim( explode( ',', $_SERVER[ $header ] )[0] );
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }
}
