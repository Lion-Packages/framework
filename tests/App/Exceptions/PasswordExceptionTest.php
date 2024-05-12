<?php

declare(strict_types=1);

namespace Tests\App\Exceptions;

use App\Exceptions\PasswordException;
use Lion\Request\Request;
use Lion\Request\Response;
use Lion\Test\Test;

class PasswordExceptionTest extends Test
{
    const MESSAGE = 'ERR';

    public function testPasswordException(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionCode(Request::HTTP_UNAUTHORIZED);
        $this->expectExceptionMessage(self::MESSAGE);

        throw new PasswordException(self::MESSAGE, Response::ERROR, Request::HTTP_UNAUTHORIZED);
    }
}
