<?php

declare(strict_types=1);

namespace Hydra\Auth;

use Hydra\Auth\Events\Attempting;
use Hydra\Auth\Events\LoggedIn;
use Hydra\Auth\Events\LoggedOut;
use Hydra\Auth\Events\LoginFailed;
use Psr\Log\LoggerInterface;

/**
 * An optional listener that writes a PSR-3 line for each auth lifecycle event —
 * a ready-made security audit trail every app tends to want the same way.
 *
 * It ships here (rather than being re-written in each app) so the behaviour
 * doesn't drift between consumers, but it is NOT registered by the auth provider:
 * an app opts in by binding its four handlers to the listener provider, keeping
 * the "framework ships the mechanism, the app decides to listen" rule intact.
 *
 * Levels match how a trail is read: a completed login/logout is `info`, a failed
 * attempt is `warning` (the signal worth watching), and the pre-check attempt is
 * `debug` (noise unless tracing). Only the identifier is recorded — never a
 * password, which the events never carry.
 */
final class LogAuthEventsListener
{
    public function __construct(
        private readonly LoggerInterface $logger,
    ) {}

    public function onAttempting(Attempting $event): void
    {
        $this->logger->debug('auth.attempting', ['username' => $event->username]);
    }

    public function onFailed(LoginFailed $event): void
    {
        $this->logger->warning('auth.login_failed', ['username' => $event->username]);
    }

    public function onLoggedIn(LoggedIn $event): void
    {
        $this->logger->info('auth.login', ['user' => $event->user->getAuthIdentifier()]);
    }

    public function onLoggedOut(LoggedOut $event): void
    {
        $this->logger->info('auth.logout', ['user' => $event->userId]);
    }
}
