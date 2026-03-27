/**
 * WP Core Secure — Admin JavaScript
 *
 * Loaded only on the WP Core Secure settings page.
 * Handles the live ACTIVE badge toggle so the card updates
 * immediately when a switch is flipped — no page reload needed.
 *
 * @package WPCoreSecure
 */

( function () {
    'use strict';

    /**
     * Toggle the ACTIVE badge and card highlight class
     * whenever a feature switch changes state.
     */
    function bindToggleBadges() {
        document.querySelectorAll( '.wpcs-sw input[type="checkbox"]' ).forEach( function ( checkbox ) {
            checkbox.addEventListener( 'change', function () {
                var card  = this.closest( '.fc' );
                var title = card.querySelector( '.fc-title' );
                var badge = title.querySelector( '.wpcs-active-badge' );

                if ( this.checked ) {
                    card.classList.add( 'active' );
                    if ( ! badge ) {
                        var span       = document.createElement( 'span' );
                        span.className = 'wpcs-active-badge';
                        span.textContent = 'ACTIVE';
                        title.appendChild( span );
                    }
                } else {
                    card.classList.remove( 'active' );
                    if ( badge ) {
                        badge.remove();
                    }
                }
            } );
        } );
    }

    /**
     * Update the "Active Rules" stat counter live as toggles change.
     */
    function bindStatsCounter() {
        var statEl = document.querySelector( '.wpcs-stat .s-num' );
        if ( ! statEl ) return;

        document.querySelectorAll( '.wpcs-sw input[type="checkbox"]' ).forEach( function ( checkbox ) {
            checkbox.addEventListener( 'change', function () {
                var active = document.querySelectorAll( '.wpcs-sw input[type="checkbox"]:checked' ).length;
                statEl.textContent = active;
            } );
        } );
    }

    // ── Init ──────────────────────────────────────────────────────────────────
    document.addEventListener( 'DOMContentLoaded', function () {
        bindToggleBadges();
        bindStatsCounter();
    } );

} () );
