/**
 * File-backed monotonically increasing counter with O_EXCL lockfile.
 *
 * Reads the integer from the file, returns it, and persists value+1.
 * The first call against a non-existent file returns 1.
 *
 * Concurrent processes contend on a sibling .lock file via O_CREAT|O_EXCL.
 * After ~50 retries (5s) we assume the lock is stale (crashed holder) and
 * force-acquire — accepts the small race-on-recovery in exchange for not
 * deadlocking forever after a crash.
 */

import * as fs from "fs";
import * as path from "path";

const MAX_RETRIES = 50;
const RETRY_INTERVAL_MS = 100;

export async function allocateCounter(counterPath: string): Promise<number> {
  fs.mkdirSync(path.dirname(counterPath), { recursive: true });
  const lockPath = counterPath + ".lock";

  let lockFd = -1;
  for (let i = 0; i < MAX_RETRIES; i++) {
    try {
      lockFd = fs.openSync(
        lockPath,
        fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
      );
      break;
    } catch {
      if (i === MAX_RETRIES - 1) {
        // Stale lock from crashed process — force acquire
        try { fs.unlinkSync(lockPath); } catch {}
        try {
          lockFd = fs.openSync(
            lockPath,
            fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
          );
        } catch { /* give up */ }
        break;
      }
      await new Promise((r) => setTimeout(r, RETRY_INTERVAL_MS));
    }
  }

  try {
    let current = 1;
    try {
      const raw = fs.readFileSync(counterPath, "utf8").trim();
      const parsed = parseInt(raw, 10);
      if (!isNaN(parsed) && parsed > 0) current = parsed;
    } catch {
      // File does not exist — start at 1
    }

    fs.writeFileSync(counterPath, String(current + 1), "utf8");
    return current;
  } finally {
    if (lockFd >= 0) try { fs.closeSync(lockFd); } catch {}
    try { fs.unlinkSync(lockPath); } catch {}
  }
}
