<?php
/**
 * WPCS_Settings
 *
 * Handles WordPress Settings API registration and input sanitization.
 * This class owns the contract for what gets stored in wp_options —
 * only whitelisted keys pass through, and values are strictly typed.
 *
 * @package WPCoreSecure
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPCS_Settings {

    /**
     * Register the settings group and sanitization callback.
     */
    public function boot() {
        add_action( 'admin_init', [ $this, 'register' ] );
    }

    /**
     * Register wpcs_settings with WordPress Settings API.
     */
    public function register() {
        register_setting(
            WPCS_Constants::SETTINGS_GROUP,
            WPCS_Constants::OPTION_KEY,
            [ $this, 'sanitize' ]
        );
    }

    /**
     * Sanitize and whitelist all incoming settings values.
     *
     * Rules:
     *  - Every boolean toggle is cast to 1 or 0 (never truthy strings)
     *  - login_limit_count is cast to int and clamped between 3 and 20
     *  - Any key not in the whitelist is silently dropped
     *
     * @param  mixed $raw Raw $_POST input from the settings form.
     * @return array      Sanitized options ready for wp_options storage.
     */
    public function sanitize( $raw ): array {
        $raw  = is_array( $raw ) ? $raw : [];
        $clean = [];

        // Boolean toggles — whitelisted from WPCS_Constants
        foreach ( WPCS_Constants::feature_keys() as $key ) {
            $clean[ $key ] = ! empty( $raw[ $key ] ) ? 1 : 0;
        }

        // Integer field: max login attempts (3–20, default 5)
        $clean['login_limit_count'] = isset( $raw['login_limit_count'] )
            ? max( 3, min( 20, (int) $raw['login_limit_count'] ) )
            : 5;

        return $clean;
    }
}
