'use strict';

const _ = require('lodash');

// Cross-file: the single `sanitize` export of ../util (one directory up).
const { sanitize } = require('../util');

// Named route handler, exported for ./server.js to wire as POST /users. The
// chain create -> sanitize (util) -> lodash and create -> lodash makes the
// old lodash dependency reachable from the entry point.
function create(req, res) {
  const clean = sanitize(req.body);
  const record = _.merge({}, { createdAt: Date.now() }, clean);
  res.json(record);
}

module.exports = { create };
