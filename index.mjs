import express from 'express';
import app from './apps/api/src/server.mjs';

// Importing Express here lets Vercel detect this root entrypoint as an Express app.
void express;

export default app;
