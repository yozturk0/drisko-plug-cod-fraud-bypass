# Drisko COD Risk Control for WooCommerce — fraud check bypass

Plugin: Drisko COD Risk Control for WooCommerce
Affected: <= 1.0.9 (current version)
Found: 30 Oct 2026
Reported by: Yusuf Ozturk

## What it does

This plugin checks if a Cash on Delivery order looks like fraud. It calls an
outside risk API, gets back ALLOW or BLOCK, and saves that answer for 5
minutes so it doesn't call the API twice for the same order.

## The bug

There's a public AJAX endpoint meant to just save that answer after the real
check runs. It never checks who's calling it, and it never checks if the
answer actually came from the real check. You can just POST `decision=ALLOW`
yourself.

The code that's supposed to stop a fake answer only checks email, phone,
address, cart and total — things the shopper already knows. It never checks
device or behavior signals, the actual fraud signals.

So: fill out checkout with your real info. The plugin's own script runs the
real check in the background, even if it returns BLOCK. Then send one extra
request saying ALLOW. Submit the order with Cash on Delivery, same info,
within 5 minutes. The real check never runs again.

## Where

`woocommerce-event-tracker.php`

```php
add_action( 'wp_ajax_nopriv_deliverease_store_decision', [ $this, 'store_decision' ] );

public function store_decision(): void
{
    check_ajax_referer( 'deliverease_store_decision', 'nonce' ); // real nonce, but public on every page

    $decision = strtoupper( sanitize_text_field( (string) ( $_POST['decision'] ?? '' ) ) );
    if ( ! in_array( $decision, [ 'ALLOW', 'BLOCK', 'REVIEW', 'ERROR' ], true ) ) {
        $decision = 'ERROR';
    }

    WC()->session->set( self::SESSION_DECISION, $decision ); // attacker picks this
    // the hash that's supposed to tie the decision to one specific order is never touched here
    WC()->session->set( self::SESSION_DECISION_AT, time() );
}
```

```php
private function recheck_decision( array $checkout_data, $order = null ): bool
{
    $context_hash = $this->context_hash( $payload );
    $decision   = strtoupper( (string) $session->get( self::SESSION_DECISION, '' ) );
    $checked_at = (int) $session->get( self::SESSION_DECISION_AT, 0 );
    $saved_hash = (string) $session->get( self::SESSION_CONTEXT_HASH, '' );

    if ( $decision !== '' && ( time() - $checked_at ) <= 300 && $saved_hash !== '' && hash_equals( $saved_hash, $context_hash ) ) {
        return $decision === 'BLOCK'; // trusts whatever decision is saved, even a forged one
    }
    // real API call only happens if the above check fails
}
```

```php
private function context_hash( array $payload ): string
{
    $context = [
        'email' => $payload['customer']['email'] ?? '',
        'phone' => $payload['customer']['phone'] ?? '',
        'address' => $payload['address'] ?? [],
        'cart'  => $payload['cart'] ?? [],
        'total' => $payload['order']['orderValue'] ?? $payload['cart']['cartValue'] ?? 0,
        // no device, behavior or fingerprint data here, only what the shopper already knows
    ];
    return hash( 'sha256', wp_json_encode( $context ) );
}
```

## How to check it yourself

1. Fill out checkout on a site with this plugin. Note the nonce from the page
   (it's public, sent to every visitor).
2. POST to `/wp-admin/admin-ajax.php`:
   `action=deliverease_store_decision&nonce=<page nonce>&decision=ALLOW`
3. Submit the order with Cash on Delivery, same cart and billing info, inside
   5 minutes.
4. Order goes through. No real fraud check ran a second time.

## Fix

Don't let the client set the decision at all. Only set it from inside the
real API call (`evaluate_checkout`), never from a separate endpoint. Or make
`store_decision` recompute the hash itself and require the decision it's
saving to match one the server actually got from the risk API this request.

## Status

Reported to the plugin's own support channel and submitted for a CVE through
MITRE's CNA of Last Resort (the plugin has 0 installs, so Patchstack's bug
bounty form won't take it — their own form has a hard install-count floor).
