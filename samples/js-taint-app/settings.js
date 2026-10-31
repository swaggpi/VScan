'use strict';

const _ = require('lodash');

// Reached cross-file from server.js:handleMerge. `body` is the attacker-
// controlled request body, bound to this parameter by the proven call site, and
// it flows straight into lodash.merge -> the sink on the proven path.
function applyDefaults(body) {
  const defaults = { role: 'user', tags: [] };
  return _.merge({}, defaults, body);
}

module.exports = { applyDefaults };
