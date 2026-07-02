<?php

declare(strict_types=1);

namespace Hydra\Auth;

use Hydra\Core\Environment;
use InvalidArgumentException;

/**
 * Typed, immutable view of the authentication settings.
 *
 * Built once from {@see Environment} by the auth service provider, the same
 * pattern as the app's config value objects and {@see \Hydra\Session\SessionConfig}.
 *
 * It holds only what genuinely varies per environment: the bcrypt work factor.
 * That is a real deployment knob — a test suite or CI runner wants a low cost so
 * hashing is fast, while production wants it as high as the hardware tolerates.
 * The internal session key the guard stores the user id under is NOT here: it is
 * a stable protocol constant on the guard, not a deployment setting (the same
 * call hydrakit/csrf made for its field/header names).
 */
final readonly class AuthConfig
{
    /** bcrypt's valid work-factor range; password_hash returns false outside it. */
    private const MIN_COST = 4;
    private const MAX_COST = 31;

    public function __construct(public int $hashCost = 12)
    {
        // A cost outside bcrypt's range makes password_hash emit a warning and
        // return false — a non-hash that would later fail every verify(). Fail
        // loud at construction instead, the same discipline as SessionConfig's
        // sameSite check and the validation package's Pattern rule.
        if ($hashCost < self::MIN_COST || $hashCost > self::MAX_COST) {
            throw new InvalidArgumentException(sprintf(
                'Auth hashCost must be between %d and %d; got %d.',
                self::MIN_COST,
                self::MAX_COST,
                $hashCost,
            ));
        }
    }

    public static function fromEnvironment(Environment $env): self
    {
        return new self(hashCost: $env->int('AUTH_HASH_COST', 12));
    }
}
