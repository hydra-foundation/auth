<?php

declare(strict_types=1);

namespace Hydra\Auth\Events;

/**
 * A credential check is about to run for {@see $username}.
 *
 * Dispatched at the top of {@see \Hydra\Auth\SessionGuard::attempt()}, before the
 * user is looked up or any password is verified — so a listener sees every login
 * attempt, successful or not. Carries only the username; no password, ever.
 */
final class Attempting
{
    public function __construct(
        public readonly string $username,
    ) {}
}
