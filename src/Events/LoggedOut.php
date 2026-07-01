<?php

declare(strict_types=1);

namespace Hydra\Auth\Events;

/**
 * The authenticated user was forgotten.
 *
 * Dispatched by {@see \Hydra\Auth\SessionGuard::logout()}. The identifier is
 * captured BEFORE the session marker is cleared and carried here, because after
 * logout the guard can no longer say who it was — {@see $userId} is null only
 * when logout() ran with nobody logged in.
 */
final class LoggedOut
{
    public function __construct(
        public readonly int|string|null $userId,
    ) {}
}
