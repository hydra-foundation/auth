<?php

declare(strict_types=1);

namespace Hydra\Auth\Events;

/**
 * A credential check for {@see $username} did not authenticate anyone.
 *
 * Dispatched by {@see \Hydra\Auth\SessionGuard::attempt()} on every failing path
 * — unknown user, passwordless account, or wrong password — deliberately without
 * distinguishing which, mirroring the guard's own uniform failure so a listener
 * (e.g. a rate limiter) can't be used to enumerate accounts. Carries only the
 * attempted username.
 */
final class LoginFailed
{
    public function __construct(
        public readonly string $username,
    ) {}
}
