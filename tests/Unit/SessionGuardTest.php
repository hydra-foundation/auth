<?php

declare(strict_types=1);

namespace Hydra\Auth\Tests\Unit;

use Hydra\Auth\Contracts\AuthenticatableInterface;
use Hydra\Auth\AuthConfig;
use Hydra\Auth\NativeHasher;
use Hydra\Auth\SessionGuard;
use Hydra\Auth\Contracts\UserProviderInterface;
use Hydra\Session\Stores\ArraySessionStore;
use PHPUnit\Framework\TestCase;

/**
 * The guard is driven against the REAL collaborators — the in-memory
 * ArraySessionStore and the real NativeHasher (at the cheapest cost) — with only
 * the app-supplied user provider faked. So these prove the actual session
 * read/write and password-verify paths, not a mock of them.
 */
final class SessionGuardTest extends TestCase
{
    private const PASSWORD = 'correct horse';

    private ArrayUserProvider $provider;
    private NativeHasher $hasher;
    private ArraySessionStore $session;

    protected function setUp(): void
    {
        $this->hasher = new NativeHasher(new AuthConfig(hashCost: 4));
        $this->provider = new ArrayUserProvider;
        $this->session = new ArraySessionStore;
        // One known user, password stored as a real hash.
        $this->provider->add('ada', new FakeUser(1, $this->hasher->hash(self::PASSWORD)));
    }

    private function guard(?ArraySessionStore $session = null): SessionGuard
    {
        return new SessionGuard($session ?? $this->session, $this->provider, $this->hasher);
    }

    public function test_starts_unauthenticated(): void
    {
        $guard = $this->guard();

        $this->assertFalse($guard->check());
        $this->assertNull($guard->user());
        $this->assertNull($guard->id());
    }

    public function test_login_authenticates_and_exposes_the_user(): void
    {
        $guard = $this->guard();
        $user = $this->provider->byUsername('ada');

        $guard->login($user);

        $this->assertTrue($guard->check());
        $this->assertSame($user, $guard->user());
        $this->assertSame(1, $guard->id());
    }

    public function test_login_regenerates_the_session_id(): void
    {
        $guard = $this->guard();
        $before = $this->session->id();

        $guard->login($this->provider->byUsername('ada'));

        // Fixation defense: the authenticated session must not reuse the
        // pre-login id, but the stored marker must survive the rotation.
        $this->assertNotSame($before, $this->session->id());
        $this->assertSame(1, $guard->id());
    }

    public function test_attempt_with_correct_credentials_logs_in(): void
    {
        $guard = $this->guard();

        $this->assertTrue($guard->attempt('ada', self::PASSWORD));
        $this->assertTrue($guard->check());
        $this->assertSame(1, $guard->id());
    }

    public function test_attempt_with_wrong_password_fails_and_does_not_log_in(): void
    {
        $guard = $this->guard();

        $this->assertFalse($guard->attempt('ada', 'wrong'));
        $this->assertFalse($guard->check());
        $this->assertNull($guard->id());
    }

    public function test_attempt_with_unknown_user_fails(): void
    {
        $guard = $this->guard();

        $this->assertFalse($guard->attempt('nobody', self::PASSWORD));
        $this->assertFalse($guard->check());
        // The missing-user branch still runs a verify (timing defense), so the
        // dummy hash was computed — but no login happened.
        $this->assertSame(1, $this->provider->byUsernameCalls);
    }

    public function test_attempt_against_a_user_with_no_password_fails(): void
    {
        // A passwordless/disabled account must never authenticate, and (per the
        // timing defense) is routed through the dummy verify just like a missing
        // user rather than short-circuiting.
        $this->provider->add('ghost', new FakeUser(2, ''));
        $guard = $this->guard();

        $this->assertFalse($guard->attempt('ghost', 'anything'));
        $this->assertFalse($guard->check());
        $this->assertNull($guard->id());
    }

    public function test_login_then_logout_then_check_within_one_request(): void
    {
        $guard = $this->guard();

        $guard->login($this->provider->byUsername('ada'));
        $this->assertTrue($guard->check());

        $guard->logout();

        // The primed cache must be cleared by logout, not left asserting a user.
        $this->assertFalse($guard->check());
        $this->assertNull($guard->user());
        $this->assertNull($guard->id());
    }

    public function test_a_non_scalar_session_value_is_not_a_login(): void
    {
        // The session surface is untyped; a non-scalar under the reserved key
        // ('_auth_id', mirrored here) must not be treated as an identifier.
        $this->session->set('_auth_id', ['not', 'a', 'scalar']);
        $guard = $this->guard();

        $this->assertNull($guard->id());
        $this->assertNull($guard->user());
        $this->assertFalse($guard->check());
    }

    public function test_logout_clears_authentication_and_regenerates_id(): void
    {
        $guard = $this->guard();
        $guard->login($this->provider->byUsername('ada'));
        $idBefore = $this->session->id();

        $guard->logout();

        $this->assertFalse($guard->check());
        $this->assertNull($guard->id());
        $this->assertNull($guard->user());
        $this->assertNotSame($idBefore, $this->session->id());
    }

    public function test_authentication_persists_to_a_later_request(): void
    {
        // Log in on one guard, then resolve on a fresh guard over the SAME store
        // — i.e. the next request. The user is restored from the session id via
        // the provider's byIdentifier lookup.
        $this->guard()->login($this->provider->byUsername('ada'));

        $next = $this->guard();
        $this->assertTrue($next->check());
        $this->assertSame(1, $next->id());
        $this->assertSame('ada', $this->userName($next->user()));
    }

    public function test_user_is_resolved_at_most_once_per_request(): void
    {
        // Fresh guard with an id already in the session (a returning request).
        $this->guard()->login($this->provider->byUsername('ada'));
        $this->provider->byIdentifierCalls = 0;

        $next = $this->guard();
        $next->user();
        $next->user();
        $next->check();

        // Three reads, one provider lookup — the per-request cache holds.
        $this->assertSame(1, $this->provider->byIdentifierCalls);
    }

    public function test_login_primes_the_cache_without_a_provider_lookup(): void
    {
        $guard = $this->guard();
        $this->provider->byIdentifierCalls = 0;

        $guard->login($this->provider->byUsername('ada'));
        $guard->user();
        $guard->check();

        // login() handed the guard the user directly; no byIdentifier needed.
        $this->assertSame(0, $this->provider->byIdentifierCalls);
    }

    private function userName(?AuthenticatableInterface $user): ?string
    {
        return $user instanceof FakeUser ? $user->username : null;
    }
}

/** A minimal AuthenticatableInterface for the tests. */
final class FakeUser implements AuthenticatableInterface
{
    public ?string $username = null;

    public function __construct(private readonly int|string $id, private readonly string $hash) {}

    public function getAuthIdentifier(): int|string
    {
        return $this->id;
    }

    public function getAuthPassword(): string
    {
        return $this->hash;
    }
}

/** In-memory user provider that records how often it is asked. */
final class ArrayUserProvider implements UserProviderInterface
{
    public int $byIdentifierCalls = 0;
    public int $byUsernameCalls = 0;

    /** @var array<string, FakeUser> */
    private array $byUsername = [];
    /** @var array<array-key, FakeUser> */
    private array $byId = [];

    public function add(string $username, FakeUser $user): void
    {
        $user->username = $username;
        $this->byUsername[$username] = $user;
        $this->byId[$user->getAuthIdentifier()] = $user;
    }

    public function byIdentifier(int|string $id): ?AuthenticatableInterface
    {
        $this->byIdentifierCalls++;

        return $this->byId[$id] ?? null;
    }

    public function byUsername(string $username): ?AuthenticatableInterface
    {
        $this->byUsernameCalls++;

        return $this->byUsername[$username] ?? null;
    }
}
