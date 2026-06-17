<?php

declare(strict_types=1);

namespace Hydra\Auth\Contracts;

/**
 * Password hashing behind a seam.
 *
 * The guard never calls PHP's password_* functions directly — it asks a hasher.
 * That keeps every credential operation in one swappable place: the shipped
 * {@see \Hydra\Auth\NativeHasher} wraps password_hash/password_verify, but an app
 * could bind a different implementation (e.g. a pepper, a legacy-hash bridge)
 * without any controller or guard change.
 *
 * Implementations must compare in constant time and must never throw on a
 * malformed or empty stored hash — {@see verify()} returns false instead, so a
 * user row with no usable password can never be logged in.
 */
interface HasherInterface
{
    /** Hash a plaintext password for storage. */
    public function hash(string $plain): string;

    /** Whether $plain matches the stored $hash, compared in constant time. */
    public function verify(string $plain, string $hash): bool;

    /**
     * Whether $hash was made with weaker parameters than the current policy.
     * A caller that has a write path to user storage can use this after a
     * successful verify() to re-hash and persist the password on the user's next
     * login — auth ships the check; performing the write is the app's to do
     * (the user provider is read-only by design).
     */
    public function needsRehash(string $hash): bool;
}
