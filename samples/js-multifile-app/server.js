'use strict';

const express = require('express');
const _ = require('lodash');

// Cross-file: a CommonJS namespace binding whose `.create` member maps to the
// single `create` export of ./controllers/user.
const ctrl = require('./controllers/user');

// Cross-file: a destructured binding of the single `sanitize` export of ./util.
const { sanitize } = require('./util');

const app = express();

// NEGATIVE: a relative specifier that resolves to no repo file -- no binding,
// so the call below must stay unresolved and fabricate no edge.
const missing = require('./does-not-exist');

// NEGATIVE: a dynamic/computed require (argument is an identifier, not a string
// literal) -- unresolvable, so the call below must stay unresolved, no edge.
const modName = './util';
const dynamic = require(modName);

// Cross-file route handler: `ctrl.create` resolves to fn:controllers/user.js:create.
app.post('/users', ctrl.create);

// Exercises the two negatives (so each is RECORDED as unresolved, proving the
// no-edge assertions are not vacuous) and a bare-package dependency call.
function bootstrap() {
  missing.run(); // module did not resolve -> unresolved, no cross-file edge
  dynamic.go(); // dynamic require -> unresolved, no cross-file edge
  // `sanitize` is a cross-file export; this proves server.js also binds it.
  const probe = sanitize({});
  // Bare `lodash` stays a dependency call (symbol lodash.cloneDeep), not a
  // cross-file edge.
  return _.cloneDeep(probe);
}

module.exports = { app, bootstrap };
