<?php

declare(strict_types=1);

namespace Hydra\Auth\Contracts;

/**
 * Where users come from — fulfilled by the application, not the package.
 *
 * This is the one contract auth deliberately leaves unbound: it cannot know your
 * storage, so the app implements it (typically a repository over its users
 * table) and binds it at the composition root. A missing binding is then a loud
 * container error, never a silent insecure default.
 *
 * It does lookups ONLY. Password verification lives entirely in the guard and
 * {@see HasherInterface}, so an implementation never touches hashes or the
 * submitted password — it just finds a user (or returns null) and hands back
 * something {@see AuthenticatableInterface}. That keeps all credential handling
 * in one audited place.
 */
interface UserProviderInterface
{
    /**
     * Find the user with this identifier, or null if none. Used to restore the
     * authenticated user from the id the guard kept in the session.
     */
    public function byIdentifier(int|string $id): ?AuthenticatableInterface;

    /**
     * Find the user with this username (or whatever single field a login is
     * keyed on — an email, say), or null if none. The guard then verifies the
     * submitted password against the returned user's stored hash; this method
     * itself performs no password check.
     */
    public function byUsername(string $username): ?AuthenticatableInterface;
}
