'use strict';

const express = require('express');
const _ = require('lodash');

const app = express();
const router = express.Router();

// Default settings merged with the user-supplied body. The merge reaches
// lodash, so the chain route -> handleUpload -> applyDefaults -> lodash is
// fully resolvable.
function applyDefaults(body) {
  const defaults = { visibility: 'private', tags: [] };
  return _.merge({}, defaults, body);
}

// Named route handler. Reachable from the POST /upload entry point.
function handleUpload(req, res) {
  const record = applyDefaults(req.body);

  // Unresolvable: `store` is an unknown object (no type information), so this
  // call must be RECORDED as unresolved and produce NO edge.
  store.persist(record);

  res.json(record);
}

function health(req, res) {
  res.json({ ok: true });
}

router.get('/health', health);
app.post('/upload', handleUpload);

// Inline anonymous handler: the entry point is created, but no fn: edge is
// fabricated to a name that does not exist.
app.get('/ping', (req, res) => res.send('pong'));

module.exports = { app, handleUpload };
