'use strict';

const _ = require('lodash');

// Exported helper reached cross-file from controllers/user.js:create.
function sanitize(body) {
  return _.pick(body || {}, ['name', 'email']);
}

module.exports = { sanitize };
