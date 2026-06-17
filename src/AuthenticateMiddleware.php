<?php

declare(strict_types=1);

namespace Hydra\Auth;

use Hydra\Auth\Contracts\GuardInterface;
use Hydra\Auth\Exceptions\AuthenticationException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Guards a route: lets the request through only when a user is authenticated,
 * otherwise throws a 401 {@see AuthenticationException} before the controller runs.
 *
 * It is a normal PSR-15 middleware, so it drops onto a route's `middleware:` list
 * (or the global stack) like any other — no new machinery. Place it INSIDE the
 * session middleware in the stack: the guard reads its state from the started
 * session.
 *
 * It does not redirect. Where an unauthenticated visitor should go is the app's
 * decision (the app owns the login route), so the middleware signals the
 * condition with a 401 and lets the app map it to a redirect for browsers and an
 * HX-Redirect for htmx.
 */
final class AuthenticateMiddleware implements MiddlewareInterface
{
    public function __construct(private readonly GuardInterface $guard) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!$this->guard->check()) {
            throw new AuthenticationException;
        }

        return $handler->handle($request);
    }
}
