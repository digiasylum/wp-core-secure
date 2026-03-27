<?php
/**
 * WPCS_Htaccess
 *
 * Handles all .htaccess read, write, toggle, and removal operations.
 *
 * Design rules enforced here:
 *  - Writes happen ONLY on settings save (update_option / add_option hooks).
 *    Never on every page request.
 *  - Every block uses named BEGIN/END markers so it is idempotent and
 *    can be cleanly removed without affecting any surrounding rules.
 *  - Deactivating the plugin triggers remove_all(), leaving .htaccess
 *    exactly as it was before the plugin was installed.
 *
 * @package WPCoreSecure
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPCS_Htaccess {

    /** @var array Current plugin options */
    private $options;

    public function __construct( array $options ) {
        $this->options = $options;
    }

    /**
     * Register hooks. Writes are triggered only by option save events.
     */
    public function boot() {
        add_action(
            'update_option_' . WPCS_Constants::OPTION_KEY,
            [ $this, 'on_save' ],
            10,
            2
        );
        add_action(
            'add_option_' . WPCS_Constants::OPTION_KEY,
            [ $this, 'on_add' ],
            10,
            2
        );
    }

    // ── Hook callbacks ────────────────────────────────────────────────────────

    /** Called when the option already exists and is being updated. */
    public function on_save( $old_value, $new_value ) {
        $this->write_all( (array) $new_value );
    }

    /** Called when the option is created for the first time. */
    public function on_add( $option, $value ) {
        $this->write_all( (array) $value );
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Write (or remove) all managed .htaccess blocks based on current options.
     * Called directly from the activation hook too.
     *
     * @param array $options
     */
    public function write_all( array $options = [] ) {
        if ( empty( $options ) ) {
            $options = $this->options;
        }

        $root_htaccess    = ABSPATH . '.htaccess';
        $uploads          = wp_upload_dir();
        $uploads_htaccess = trailingslashit( $uploads['basedir'] ) . '.htaccess';

        // 1. XML-RPC — root .htaccess
        $this->toggle(
            $root_htaccess,
            'xmlrpc-block',
            "<Files xmlrpc.php>\n    Order Deny,Allow\n    Deny from all\n</Files>",
            ! empty( $options['disable_xmlrpc'] )
        );

        // 2. Directory indexing — root .htaccess
        $this->toggle(
            $root_htaccess,
            'no-indexes',
            'Options -Indexes',
            ! empty( $options['disable_directory_browsing'] )
        );

        // 3. Protect wp-config.php — root .htaccess
        $this->toggle(
            $root_htaccess,
            'protect-wpconfig',
            "<Files wp-config.php>\n    Order Allow,Deny\n    Deny from all\n</Files>",
            ! empty( $options['protect_wpconfig'] )
        );

        // 4. Block PHP execution — uploads .htaccess
        $this->toggle(
            $uploads_htaccess,
            'no-php-uploads',
            "<Files *.php>\n    Order Deny,Allow\n    Deny from all\n</Files>",
            ! empty( $options['disable_php_execution'] )
        );
    }

    /**
     * Remove every block this plugin has ever written to any .htaccess file.
     * Called from the deactivation hook.
     */
    public function remove_all() {
        $root_htaccess = ABSPATH . '.htaccess';
        foreach ( [ 'xmlrpc-block', 'no-indexes', 'protect-wpconfig' ] as $id ) {
            $this->toggle( $root_htaccess, $id, '', false );
        }

        $uploads          = wp_upload_dir();
        $uploads_htaccess = trailingslashit( $uploads['basedir'] ) . '.htaccess';
        $this->toggle( $uploads_htaccess, 'no-php-uploads', '', false );
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Add or remove a single named block in an .htaccess file.
     *
     * @param string $file   Absolute path to the .htaccess file.
     * @param string $id     Short block identifier, e.g. 'xmlrpc-block'.
     * @param string $rules  The lines to place between the BEGIN/END markers.
     * @param bool   $enable TRUE to add the block, FALSE to remove it.
     */
    private function toggle( string $file, string $id, string $rules, bool $enable ) {
        $begin = "# BEGIN WP-Core-Secure: {$id}";
        $end   = "# END WP-Core-Secure: {$id}";
        $block = "{$begin}\n{$rules}\n{$end}";
        $dir   = dirname( $file );

        if ( $enable ) {
            if ( ! is_dir( $dir ) ) {
                wp_mkdir_p( $dir );
            }
            $existing = file_exists( $file ) ? file_get_contents( $file ) : '';
            // Block already present — do nothing (idempotent)
            if ( strpos( $existing, $begin ) !== false ) {
                return;
            }
            file_put_contents( $file, "\n" . $block . "\n", FILE_APPEND | LOCK_EX );
        } else {
            if ( ! file_exists( $file ) ) {
                return;
            }
            $content = file_get_contents( $file );
            $pattern = '/\n?' . preg_quote( $begin, '/' ) . '.*?' . preg_quote( $end, '/' ) . '\n?/s';
            $cleaned = preg_replace( $pattern, '', $content );
            if ( $cleaned !== $content ) {
                file_put_contents( $file, $cleaned, LOCK_EX );
            }
        }
    }
}
