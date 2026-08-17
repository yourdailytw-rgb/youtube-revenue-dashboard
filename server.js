/**
 * Compatibility shim.
 *
 * v1 lived in a single root-level server.js and the Railway service may still
 * have `node server.js` pinned as its start command. The real entry point is
 * now server/index.js — this file exists purely so an existing deploy config
 * keeps working. Safe to delete once Railway's start command is `npm start`.
 */
require('./server/index.js');
