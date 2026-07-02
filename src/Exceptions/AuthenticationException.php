<?php

declare(strict_types=1);

namespace Hydra\Auth\Exceptions;

use Hydra\Http\Exceptions\HttpException;
use Throwable;

/**
 * A request reached a guarded route without an authenticated user: HTTP 401.
 *
 * Like the http package's NotFoundException and hydrakit/csrf's
 * TokenMismatchException, this is a typed HttpException so the app's outermost
 * ErrorHandlerMiddleware renders it — the guard middleware only throws. The
 * package stops at the 401; turning that into a redirect to a login page (a
 * 302 for a browser, an HX-Redirect for htmx) is the app's policy, because the
 * login route is the app's to own.
 */
final class AuthenticationException extends HttpException
{
    public function __construct(string $message = 'Unauthenticated.', ?Throwable $previous = null)
    {
        parent::__construct(401, $message, [], $previous);
    }
}
