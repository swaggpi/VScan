// Minimal server for the bun transitive-dependency fixture.
//
// The point of this sample is the dependency tree resolved from bun.lock (a
// JSONC lockfile with trailing commas), not the call graph. "express" is the
// only DECLARED (direct) dep in package.json; bun.lock resolves it to the exact
// version 4.18.2 and surfaces "accepts" -- express's own dependency, never named
// in package.json -- as a TRANSITIVE dep (direct=False). See README.md.

import express from "express"; // declared/direct, imported but never called

export function makeApp() {
  return express;
}
