'use strict';

// Minimal Express app for the transitive-dependency fixture. The point of this
// sample is the dependency *tree*, not the call graph: express is the only
// DECLARED dep, while minimist and qs are TRANSITIVE (resolved by the lockfile,
// never named in package.json and never required here). See README.md.

const express = require('express');

const app = express();

// A named route handler so the app scans cleanly (an entrypoint wired to a
// traversable handler), matching the js-taint-app pattern. The body makes NO
// calls, so the reachable region is fully resolved -- which is deliberate: it
// lets this one fixture prove the soundness override. In that fully-resolved
// region the DIRECT, uncalled express dep is honestly `unreachable`, while the
// TRANSITIVE, equally-uncalled minimist/qs stay `potentially_reachable`. Same
// region, same edge-absence -- so the verdict split can only come from the
// `direct` flag, not from "has no incoming call edge".
function handleHealth(req, res) {
  const status = 'ok';
  return status;
}

app.get('/health', handleHealth);

module.exports = { app };
