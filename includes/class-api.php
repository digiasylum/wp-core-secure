<?php
/**
 * WPCS_API
 *
 * REST API access control features:
 *  - Restrict the full REST API to authenticated users only
 *  - Block the /wp/v2/users endpoint for all requests (regardless of auth)
 *
 * Note: blocking /wp/v2/users for unauthenticated users specifically is
 * handled in WPCS_Login alongside the ?author= enumeration block, since
 * both are user-enumeration vectors. This class handles the broader
 * "lock the whole API" and "remove users endpoint entirely" controls.
 *
 * @package WPCoreSecure
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPCS_API {

    /** @var array Plugin options */
    private $options;

    public function __construct( array $options ) {
        $this->options = $options;
    }

    /**
     * Register REST API restriction hooks.
     */
    public function boot() {
        add_action( 'init', [ $this, 'apply' ], 1 );
    }

    /**
     * Apply enabled API control rules.
     */
    public function apply() {
        $o = $this->options;

        $this->maybe_restrict_rest_to_logged_in( $o );
        $this->maybe_block_users_endpoint( $o );
    }

    // ── Feature implementations ───────────────────────────────────────────────

    /**
     * Return 401 for any unauthenticated REST API request.
     * This is a broad lock — see the warn label in WPCS_Constants.
     */
    private function maybe_restrict_rest_to_logged_in( array $o ) {
        if ( empty( $o['disable_rest_api_for_guests'] ) ) return;

        add_filter( 'rest_authentication_errors', static function ( $result ) {
            if ( ! is_user_logged_in() ) {
                return new WP_Error(
                    'wpcs_rest_restricted',
                    __( 'REST API access is restricted to authenticated users.', 'wp-core-secure' ),
                    [ 'status' => 401 ]
                );
            }
            return $result;
        } );
    }

    /**
     * Remove /wp/v2/users and /wp/v2/users/{id} from the endpoint registry
     * for ALL requests, regardless of authentication status.
     *
     * Use this when you want to block the users endpoint completely.
     * For blocking only for guests, see WPCS_Login::remove_users_endpoint_for_guests().
     */
    private function maybe_block_users_endpoint( array $o ) {
        if ( empty( $o['block_rest_users_endpoint'] ) ) return;

        add_filter( 'rest_endpoints', [ $this, 'remove_users_endpoint' ] );
    }

    // ── Callbacks ─────────────────────────────────────────────────────────────

    /**
     * Unset the users REST endpoints from the registry.
     *
     * @param  array $endpoints All registered endpoints.
     * @return array
     */
    public function remove_users_endpoint( array $endpoints ): array {
        unset( $endpoints['/wp/v2/users'] );
        unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
        return $endpoints;
    }
}
