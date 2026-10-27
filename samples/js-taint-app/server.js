'use strict';

// Express app exercising the sound JavaScript taint adapter. The ground-truth
// taint verdict for every route is documented in README.md.

const express = require('express');
const yaml = require('js-yaml');

// Cross-file helper: the proven path /merge -> handleMerge -> applyDefaults
// carries the lodash sink one file over.
const settings = require('./settings');

const app = express();

// POSITIVE: the attacker-controlled request body flows, cross-file, into
// lodash.merge -> ground-truth `tainted` (source req.body, sink lodash.merge).
function handleMerge(req, res) {
  const merged = settings.applyDefaults(req.body);
  res.json(merged);
}

// NEGATIVE (straight-line rebind to a constant): the attacker body is
// overwritten by a constant before the js-yaml sink, so the sink never sees it.
function handleParse(req, res) {
  let doc = req.body;
  doc = 'name: default';
  res.json(yaml.load(doc));
}

// NEGATIVE (constant-only sink): js-yaml.load is called with a literal.
function handleStatic(req, res) {
  res.json(yaml.load('mode: readonly'));
}

// NEGATIVE (no sink): reads a request source but never passes it to a dep call.
function handleEcho(req, res) {
  const term = req.query.term;
  res.json({ echo: term });
}

app.post('/merge', handleMerge);
app.post('/parse', handleParse);
app.get('/static', handleStatic);
app.get('/echo', handleEcho);

module.exports = { app };
