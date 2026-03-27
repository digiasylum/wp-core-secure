<?php
/**
 * WPCS_Headers
 *
 * Sends HTTP security response headers based on enabled settings.
 * Headers are sent via the `send_headers` WordPress hook — before any
 * HTML output — and are compatible with most page caching plugins.
 *
 * Features handled here:
 *  - HSTS + Content-Security-Policy + Permissions-Policy
 *  - X-Frame-Options (clickjacking protection)
 *  - X-Content-Type-Options + X-XSS-Protection
 *  - Referrer-Policy
 *
 * @package WPCoreSecure
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPCS_Headers {

    /** @var array Plugin options */
    private $options;

    public function __construct( array $options ) {
        $this->options = $options;
    }

    /**
     * Register the send_headers hook only if at least one header feature is on.
     */
    public function boot() {
        $relevant = [
            'security_headers',
            'clickjacking_protection',
            'content_type_nosniff',
            'referrer_policy',
        ];

        foreach ( $relevant as $key ) {
            if ( ! empty( $this->options[ $key ] ) ) {
                add_action( 'send_headers', [ $this, 'send' ] );
                return; // one hook registration is enough
            }
        }
    }

    /**
     * Emit all enabled security headers.
     * Called on the `send_headers` action.
     */
    public function send() {
        $o = $this->options;

        // ── HSTS + CSP + Permissions-Policy ──────────────────────────────────
        if ( ! empty( $o['security_headers'] ) ) {

            // Force HTTPS for 1 year, including subdomains (preload-ready)
            header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' );

            // Base CSP — allows same-origin scripts/styles plus inline
            // (adjust if you have a strict CSP requirement)
            header(
                "Content-Security-Policy: " .
                "default-src 'self'; " .
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " .
                "style-src 'self' 'unsafe-inline'; " .
                "img-src * data:; " .
                "font-src *;"
            );

            // Restrict browser feature APIs
            header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
        }

        // ── Clickjacking protection ───────────────────────────────────────────
        if ( ! empty( $o['clickjacking_protection'] ) ) {
            header( 'X-Frame-Options: SAMEORIGIN' );
        }

        // ── MIME sniffing + XSS ───────────────────────────────────────────────
        if ( ! empty( $o['content_type_nosniff'] ) ) {
            header( 'X-Content-Type-Options: nosniff' );
            header( 'X-XSS-Protection: 1; mode=block' );
        }

        // ── Referrer policy ───────────────────────────────────────────────────
        if ( ! empty( $o['referrer_policy'] ) ) {
            header( 'Referrer-Policy: strict-origin-when-cross-origin' );
        }
    }
}
