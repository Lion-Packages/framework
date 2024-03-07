<?php

define('LION_START', microtime(true));

/**
 * -----------------------------------------------------------------------------
 * Register The Auto Loader
 * -----------------------------------------------------------------------------
 * Composer provides a convenient, automatically generated class loader for
 * this application
 * -----------------------------------------------------------------------------
 **/

require_once(__DIR__ . '/../vendor/autoload.php');

use Dotenv\Dotenv;
use Lion\Bundle\Helpers\Http\Routes;
use Lion\Bundle\HttpKernel;
use Lion\DependencyInjection\Container;
use Lion\Request\Request;
use Lion\Route\Route;
use Lion\Security\RSA;

/**
 * -----------------------------------------------------------------------------
 * Register environment variable loader automatically
 * -----------------------------------------------------------------------------
 * .dotenv provides an easy way to access environment variables with $_ENV
 * -----------------------------------------------------------------------------
 **/

Dotenv::createImmutable(__DIR__ . '/../')->load();

/**
 * -----------------------------------------------------------------------------
 * Import route for RSA
 * -----------------------------------------------------------------------------
 * Load default route for RSA
 * -----------------------------------------------------------------------------
 **/

(new RSA)->setUrlPath(storage_path(env('RSA_URL_PATH', 'keys/')));

/**
 * -----------------------------------------------------------------------------
 * Cross-Origin Resource Sharing (CORS) Configuration
 * -----------------------------------------------------------------------------
 * Here you can configure your settings for cross-origin resource
 * sharing or "CORS". This determines which cross-origin operations
 * can be executed in web browsers.
 * -----------------------------------------------------------------------------
 **/

foreach (require_once(__DIR__ . '/../config/cors.php') as $header => $value) {
    Request::header($header, $value);
}

/**
 * -----------------------------------------------------------------------------
 * Use rules by routes
 * -----------------------------------------------------------------------------
 * use whatever rules you want to validate input data
 * -----------------------------------------------------------------------------
 **/

(new Container)->injectDependencies((new HttpKernel))->validateRules();

/**
 * -----------------------------------------------------------------------------
 * Database initialization
 * -----------------------------------------------------------------------------
 * */

include_once(__DIR__ . '/../config/database.php');

/**
 * -----------------------------------------------------------------------------
 * Email initialization
 * -----------------------------------------------------------------------------
 * */

include_once(__DIR__ . '/../config/email.php');

/**
 * -----------------------------------------------------------------------------
 * Local zone configuration
 * -----------------------------------------------------------------------------
 */

date_default_timezone_set(env('SERVER_DATE_TIMEZONE', 'America/Bogota'));

/**
 * -----------------------------------------------------------------------------
 * Web Routes
 * -----------------------------------------------------------------------------
 * Here is where you can register web routes for your application
 * -----------------------------------------------------------------------------
 **/

Route::init();
Route::addMiddleware(Routes::getMiddleware());
include_once(__DIR__ . '/../routes/web.php');
Route::get('route-list', fn() => Route::getFullRoutes(), ['protect-route-list']);
Route::dispatch();
