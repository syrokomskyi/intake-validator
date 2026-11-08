#!/usr/bin/env node
// RFC-1540: published @warpgogol/* packages ship TypeScript sources and Node
// does not strip types under node_modules, so the bin registers the tsx ESM
// loader before importing the CLI.
import { register } from "tsx/esm/api";

register();
const { runCli } = await import("../src/cli.ts");
const outcome = await runCli(process.argv.slice(2));
process.stdout.write(outcome.stdout);
process.stderr.write(outcome.stderr);
process.exit(outcome.exitCode);
