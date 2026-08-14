/**
 * The Worker entry point.
 *
 * Deliberately three lines: everything worth testing lives in handler.ts and
 * keyring.ts, which run without a Worker at all.
 */
import type { WorkerScope } from './handler';
import { installHandler } from './handler';

installHandler(self as unknown as WorkerScope);
