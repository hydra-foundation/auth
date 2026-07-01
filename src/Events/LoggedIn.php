<?php

declare(strict_types=1);

namespace Hydra\Auth\Events;

use Hydra\Auth\Contracts\AuthenticatableInterface;

/**
 * A user was authenticated for subsequent requests.
 *
 * Dispatched by {@see \Hydra\Auth\SessionGuard::login()} after the session marker
 * is written and the per-request cache is primed — so a listener that reads the
 * guard already sees the logged-in state. Fires for both a successful
 * {@see \Hydra\Auth\SessionGuard::attempt()} and a direct login(). Carries the
 * user, the only place downstream can reach the identifier or profile.
 */
final class LoggedIn
{
    public function __construct(
        public readonly AuthenticatableInterface $user,
    ) {}
}
