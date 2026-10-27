<?php

namespace App;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Route;
use Monolog\Logger;

/**
 * Handles importing records from an upstream source.
 *
 * The controller and its route registration live in one file because this
 * analyzer is single-file: the route_to_handler edge can only be emitted when
 * the handler method is defined in the same file as the route (see the
 * php_analyzer module docstring).
 */
class ImportController
{
    public function store($service)
    {
        // Intra-file call: resolves to ImportController.validate (same class).
        $this->validate();

        // Dynamic dispatch on an argument of unknown type: MUST stay
        // unresolved -- no call edge is emitted for this.
        $service->run();

        return true;
    }

    private function validate()
    {
        return true;
    }
}

// Laravel-style route registration (one framework style, used consistently).
// The handler is a [Controller::class, 'method'] pair whose method is defined
// above in this same file, so a route_to_handler edge is emitted to it.
Route::post('/import', [ImportController::class, 'store']);
