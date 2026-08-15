<?php

namespace App\Support;

use App\Enums\AuditAction;
use App\Models\User;
use Illuminate\Support\Carbon;

/**
 * A signed claim from the browser about something the server could not see.
 *
 * Unlocking a vault and revealing a secret both happen entirely inside the tab —
 * the Worker unwraps a key, a component renders a string, and nothing crosses
 * the network. Those are also the two moments an investigation cares about most,
 * so the browser reports them, and signs them so that "the browser said so" and
 * "the server says the browser said so" are distinguishable.
 *
 * The signature is over the exact bytes stored in `signed_payload`, verbatim,
 * for the same reason `grant_payload` is stored verbatim: rebuilding the JSON
 * from columns at verification time would invalidate every signature the day the
 * serialisation changed.
 *
 *   signature = Ed25519( "vault:audit:v1" ‖ 0x00 ‖ payload )
 *
 * Domain-separated because a self-signature, a grant and this are all Ed25519
 * signatures by one key. Without the separator, a signature over one could be
 * presented as another.
 */
final class AuditStatement
{
    /** Matches AUDIT_SIGNATURE_CONTEXT in resources/js/crypto/audit.ts. */
    public const CONTEXT = 'vault:audit:v1';

    public const VERSION = 1;

    private const SIGNATURE_BYTES = 64;

    private const PUBLIC_KEY_BYTES = 32;

    /**
     * How far a statement's own timestamp may sit from the server's clock.
     *
     * Not a security boundary — a client with the key can sign any timestamp it
     * likes inside the window. It bounds *replay*: without it, a captured
     * request could be posted back indefinitely to bury a real event under
     * plausible-looking noise, in a table that by design can never be cleaned up.
     */
    private const CLOCK_SKEW_SECONDS = 300;

    /**
     * Checks a signed statement against the action and subject it accompanies.
     *
     * **The comparison is the point, not the signature alone.** A valid
     * signature proves only that this user once signed *some* statement; it is
     * matching the signed fields against the event being recorded that turns
     * that into evidence about this event. The same reasoning as `verifyGrant`
     * comparing a signed grant with the membership row it arrived on.
     *
     * Returns null when it verifies, or a reason when it does not.
     */
    public static function reject(
        User $user,
        AuditAction $action,
        string $subjectUuid,
        string $payload,
        string $signatureBase64,
    ): ?string {
        $publicKey = $user->identity?->ed25519_public_key->bytes() ?? '';

        if (strlen($publicKey) !== self::PUBLIC_KEY_BYTES) {
            return 'This account has no usable signing key, so it cannot report client-side events.';
        }

        $signature = base64_decode($signatureBase64, true);

        if ($signature === false || strlen($signature) !== self::SIGNATURE_BYTES) {
            return 'The signature is not '.self::SIGNATURE_BYTES.' bytes.';
        }

        $claim = self::parse($payload);

        if ($claim === null) {
            return 'The signed statement could not be read.';
        }

        if ($claim['action'] !== $action->value) {
            return "The signed statement is about [{$claim['action']}], not [{$action->value}].";
        }

        if ($claim['subjectUuid'] !== $subjectUuid) {
            return 'The signed statement names a different subject than the request does.';
        }

        if (abs(Carbon::parse($claim['at'])->diffInSeconds(now())) > self::CLOCK_SKEW_SECONDS) {
            return 'The signed statement is too old, or dated too far ahead, to be recorded now.';
        }

        if (! sodium_crypto_sign_verify_detached($signature, self::signedBytes($payload), $publicKey)) {
            return 'The signature does not match this account’s signing key.';
        }

        return null;
    }

    /**
     * @return ?array{action: string, subjectUuid: string, at: string}
     */
    public static function parse(string $payload): ?array
    {
        $decoded = json_decode($payload, true);

        if (! is_array($decoded) || ($decoded['v'] ?? null) !== self::VERSION) {
            return null;
        }

        $action = $decoded['action'] ?? null;
        $subjectUuid = $decoded['subjectUuid'] ?? null;
        $at = $decoded['at'] ?? null;

        if (! is_string($action) || ! is_string($subjectUuid) || ! is_string($at)) {
            return null;
        }

        if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $at) !== 1) {
            return null;
        }

        return ['action' => $action, 'subjectUuid' => $subjectUuid, 'at' => $at];
    }

    public static function signedBytes(string $payload): string
    {
        return self::CONTEXT."\0".$payload;
    }
}
