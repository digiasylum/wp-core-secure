<?php
/**
 * Settings page view.
 *
 * Loaded by WPCS_Admin::render_page().
 * Contains ONLY presentation — no business logic, no direct DB calls.
 * All data comes from WPCS_Constants (feature metadata, section list).
 *
 * @package WPCoreSecure
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

$options     = (array) get_option( WPCS_Constants::OPTION_KEY, [] );
$saved       = ! empty( $_GET['settings-updated'] );
$limit       = isset( $options['login_limit_count'] ) ? (int) $options['login_limit_count'] : 5;
$feature_meta = WPCS_Constants::feature_meta();
$sections    = WPCS_Constants::sections();

// Count active rules for the stats row
$active_count = 0;
foreach ( WPCS_Constants::feature_keys() as $k ) {
    if ( ! empty( $options[ $k ] ) ) $active_count++;
}
$total_count = count( WPCS_Constants::feature_keys() );
?>

<div id="wpcs">

    <!-- ── Developer Card ───────────────────────────────────────────────── -->
    <div class="wpcs-dev-card">
        <div class="wpcs-dev-logo"><i class="fa-solid fa-d"></i></div>
        <div class="wpcs-dev-info">
            <h3><?php esc_html_e( 'Developed by Digi Asylum & Umesh Kumar Sahai', 'wp-core-secure' ); ?></h3>
            <p><?php esc_html_e( 'A lightweight WordPress hardening plugin — zero telemetry, no subscriptions, just security.', 'wp-core-secure' ); ?></p>
            <div class="wpcs-dev-links">
                <a href="https://digiasylum.com" target="_blank" rel="noopener noreferrer">
                    <i class="fa-solid fa-globe"></i> digiasylum.com
                </a>
                <a href="https://www.linkedin.com/in/umeshkumarsahai/" target="_blank" rel="noopener noreferrer">
                    <i class="fa-brands fa-linkedin"></i> Umesh Kumar Sahai
                </a>
                <a href="https://github.com/digiasylum/wp-core-secure" target="_blank" rel="noopener noreferrer">
                    <i class="fa-brands fa-github"></i> GitHub
                </a>
                <a href="mailto:connect@digiasylum.com">
                    <i class="fa-solid fa-envelope"></i> Support
                </a>
            </div>
        </div>
        <div class="wpcs-dev-version">v<?php echo esc_html( WPCS_VERSION ); ?></div>
    </div>

    <!-- ── Hero Banner ──────────────────────────────────────────────────── -->
    <div class="wpcs-hero">
        <div class="wpcs-hero-icon"><i class="fa-solid fa-shield-halved"></i></div>
        <div>
            <h1>
                <?php esc_html_e( 'WP Core Secure', 'wp-core-secure' ); ?>
                <span class="wpcs-badge">v<?php echo esc_html( WPCS_VERSION ); ?></span>
            </h1>
            <p><?php esc_html_e( 'Multi-layer WordPress hardening — brute force protection, HTTP security headers, login security, user enumeration blocking, and more. No cloud. No calls home.', 'wp-core-secure' ); ?></p>
        </div>
    </div>

    <!-- ── Stats Row ────────────────────────────────────────────────────── -->
    <div class="wpcs-stats">
        <div class="wpcs-stat">
            <div class="s-num"><?php echo esc_html( $active_count ); ?></div>
            <div class="s-label"><?php esc_html_e( 'Active Rules', 'wp-core-secure' ); ?></div>
        </div>
        <div class="wpcs-stat">
            <div class="s-num"><?php echo esc_html( $total_count ); ?></div>
            <div class="s-label"><?php esc_html_e( 'Total Features', 'wp-core-secure' ); ?></div>
        </div>
        <div class="wpcs-stat">
            <div class="s-num"><?php echo count( $sections ); ?></div>
            <div class="s-label"><?php esc_html_e( 'Security Groups', 'wp-core-secure' ); ?></div>
        </div>
        <div class="wpcs-stat">
            <div class="s-num">0</div>
            <div class="s-label"><?php esc_html_e( 'External Calls', 'wp-core-secure' ); ?></div>
        </div>
    </div>

    <!-- ── Save notice ──────────────────────────────────────────────────── -->
    <?php if ( $saved ) : ?>
    <div class="wpcs-notice ok">
        <i class="fa-solid fa-circle-check"></i>
        <span>
            <strong><?php esc_html_e( 'Settings saved.', 'wp-core-secure' ); ?></strong>
            <?php esc_html_e( 'Your security configuration has been updated.', 'wp-core-secure' ); ?>
        </span>
    </div>
    <?php endif; ?>

    <!-- ── Settings form ────────────────────────────────────────────────── -->
    <form method="post" action="options.php">
        <?php settings_fields( WPCS_Constants::SETTINGS_GROUP ); ?>

        <?php foreach ( $sections as $section ) : ?>

        <!-- Section divider -->
        <div class="section-sep">
            <span class="sep-line"></span>
            <span class="sep-label">
                <i class="fa-solid <?php echo esc_attr( $section['icon'] ); ?>"></i>
                <?php echo wp_kses_post( $section['label'] ); ?>
            </span>
            <span class="sep-line"></span>
        </div>

        <?php foreach ( $section['features'] as $key ) :
            $meta      = $feature_meta[ $key ] ?? [];
            $checked   = ! empty( $options[ $key ] );
            $has_count = ! empty( $meta['has_count'] );
        ?>

        <!-- Feature card -->
        <div class="fc<?php echo $checked ? ' active' : ''; ?>" data-key="<?php echo esc_attr( $key ); ?>">

            <!-- Icon -->
            <div class="fc-icon <?php echo esc_attr( $meta['ic'] ?? '' ); ?>">
                <i class="fa-solid <?php echo esc_attr( $meta['icon'] ?? '' ); ?>"></i>
            </div>

            <!-- Label + description + optional warning -->
            <div class="fc-body">
                <div class="fc-title">
                    <?php echo wp_kses_post( $meta['label'] ?? $key ); ?>
                    <?php if ( $checked ) : ?>
                    <span class="wpcs-active-badge"><?php esc_html_e( 'ACTIVE', 'wp-core-secure' ); ?></span>
                    <?php endif; ?>
                </div>
                <div class="fc-desc"><?php echo wp_kses_post( $meta['desc'] ?? '' ); ?></div>

                <?php if ( ! empty( $meta['warn'] ) ) : ?>
                <div class="fc-warn"><?php echo wp_kses_post( $meta['warn'] ); ?></div>
                <?php endif; ?>

                <?php if ( $has_count ) : ?>
                <div class="fc-extra">
                    <label>
                        <?php esc_html_e( 'Max attempts before lockout:', 'wp-core-secure' ); ?>
                        <input type="number"
                               name="wpcs_settings[login_limit_count]"
                               value="<?php echo esc_attr( $limit ); ?>"
                               min="3"
                               max="20">
                    </label>
                </div>
                <?php endif; ?>
            </div>

            <!-- Toggle switch -->
            <label class="wpcs-sw" title="<?php echo esc_attr( sprintf( __( 'Toggle %s', 'wp-core-secure' ), strip_tags( $meta['label'] ?? $key ) ) ); ?>">
                <input type="checkbox"
                       name="wpcs_settings[<?php echo esc_attr( $key ); ?>]"
                       value="1"
                       <?php checked( $checked ); ?>>
                <span class="wpcs-slider"></span>
            </label>

        </div><!-- .fc -->

        <?php endforeach; // features ?>
        <?php endforeach; // sections ?>

        <!-- Save button -->
        <div class="wpcs-actions">
            <button type="submit" class="wpcs-save">
                <i class="fa-solid fa-floppy-disk"></i>
                <?php esc_html_e( 'Save Settings', 'wp-core-secure' ); ?>
            </button>
        </div>

    </form>

</div><!-- #wpcs -->
