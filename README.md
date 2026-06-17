# Hydra Auth

Authentication — identity only. It answers *who is logged in* and provides the
verbs to change that (attempt/login/logout), behind a swappable guard. It does
not do permissions: those are `hydra/authorization`. It does not know your
users: that one contract is left for the app to fulfil.

## The guard

A controller injects `GuardInterface` and asks it questions (`check`, `user`,
`id`) or drives a login (`attempt`, `login`, `logout`). It never touches the
session key, the user provider, or the hasher directly — the guard coordinates
those. `SessionGuard` keeps a single identifier in the session, resolves the
user at most once per request, and regenerates the session id on both login and
logout (fixation defense). Binding the interface keeps the mechanism swappable:
a token guard for an API could replace it without a controller change.

```php
if ($guard->attempt($username, $password)) {
    // logged in; session id regenerated
}
```

## What the app must supply

`UserProviderInterface` is the one contract auth deliberately leaves unbound —
it cannot know your storage. The app implements it (typically a repository over
its users table) and binds it at the composition root; a missing binding is a
loud container error, never a silent insecure default. The provider does lookups
*only* — it never sees a password. The app's user entity implements
`AuthenticatableInterface` (a stable identifier + the stored hash); auth never
sees the rest of the model.

## Config

`AuthConfig` holds only what genuinely varies per environment — the bcrypt work
factor (`AUTH_HASH_COST`, default 12) — and validates it against bcrypt's range
at construction. The session key the guard uses is a stable protocol constant on
the guard, not a deployment setting.
