/**
 * The crypto core.
 *
 * Standalone by design: this module imports nothing from the application or its
 * framework, so it can be reasoned about and tested on its own. ESLint enforces
 * that, and vitest holds it at 100% coverage.
 *
 * Read docs/03-cryptographic-design.md before changing anything here. The rules
 * that matter most:
 *
 *   1. Every seal() binds its ciphertext to a record via AAD. The parameter is
 *      required and has no default (SR4).
 *   2. Every failure throws. Nothing returns null to mean "could not decrypt"
 *      (SR3).
 *   3. Key material never leaves the Worker (SR7).
 */

export { AAD_CONTEXTS, buildAad, type AadContext, type AadParams } from './aad';

export { decodeBase32, encodeBase32, group } from './encoding';

export { ALG_XCHACHA20_POLY1305, ENVELOPE_VERSION, MIN_ENVELOPE_LENGTH, open, seal } from './envelope';

export {
    CryptoError,
    IntegrityError,
    InvalidParameterError,
    KeyUnavailableError,
    MalformedEnvelopeError,
    UnsupportedEnvelopeError,
} from './errors';

export {
    computeFingerprint,
    formatFingerprint,
    generateIdentity,
    signPublicKeys,
    verifyPublicKeys,
    type Identity,
} from './identity';

export {
    deriveFromPassword,
    deriveRecoveryKek,
    generateKdfSalt,
    generateKey,
    generateRecoveryCode,
    generateX25519KeyPair,
    openSealed,
    sealTo,
    unwrapKey,
    wrapKey,
    type KeyPair,
    type RecoveryCode,
    type StretchedPassword,
} from './keys';

export {
    DEFAULT_KDF_PARAMS,
    KEY_LENGTH,
    NONCE_LENGTH,
    TAG_LENGTH,
    concat,
    constantTimeEqual,
    deriveKey,
    hash256,
    randomBytes,
    utf8ToBytes,
    zeroise,
    type KdfParams,
} from './primitives';
