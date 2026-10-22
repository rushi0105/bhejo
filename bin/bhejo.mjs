#!/usr/bin/env node
import { main } from '../src/cli.mjs';

main(process.argv.slice(2)).catch((err) => {
  if (err?.name === 'CliError') {
    console.error(`bhejo: ${err.message}`);
    process.exitCode = err.exitCode ?? 1;
    return;
  }
  console.error(`bhejo: ${err?.message ?? err}`);
  if (process.env.BHEJO_DEBUG) console.error(err);
  process.exitCode = 1;
});
