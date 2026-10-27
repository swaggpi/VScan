<?php

namespace App;

use Illuminate\Support\Facades\Route;
use Monolog\Logger; // declared/direct (monolog/monolog), imported but never called

/**
 * Minimal controller for the composer transitive-dependency fixture.
 *
 * The point of this sample is the dependency *tree*, not the call graph:
 * `monolog/monolog` is the only DECLARED dep (composer.json `require`), while
 * `psr/log` is TRANSITIVE -- resolved only by composer.lock and never named in
 * the manifest.
 *
 * The routed handler body makes NO calls, so the reachable region is fully
 * resolved. In that region the DIRECT, uncalled `monolog/monolog` dep is
 * honestly `unreachable`, while the TRANSITIVE `psr/log` stays
 * `potentially_reachable`: same region, same edge-absence -- the verdict split
 * can only come from the `direct` flag. See README.md.
 */
class HealthController
{
    public function check()
    {
        $status = 'ok';
        return $status;
    }
}

// Laravel-style route registration whose handler is a [Controller::class,
// 'method'] pair defined above in this same file.
Route::get('/health', [HealthController::class, 'check']);
