/**
 * Root Agent Client — call the privileged root agent daemon via Unix socket.
 */

import * as net from "net";

const SOCKET_PATH = "/run/blockhost/root-agent.sock";
const DEFAULT_TIMEOUT = 300_000; // 300s in ms

class RootAgentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RootAgentError";
  }
}

export async function callRootAgent(
  action: string,
  params: Record<string, unknown> = {},
  timeout: number = DEFAULT_TIMEOUT,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(SOCKET_PATH);
    socket.setTimeout(timeout);

    const msg = Buffer.from(JSON.stringify({ action, params }), "utf-8");
    const header = Buffer.alloc(4);
    header.writeUInt32BE(msg.length, 0);

    let responseBuffer = Buffer.alloc(0);
    let expectedLength: number | null = null;

    socket.on("connect", () => {
      socket.write(Buffer.concat([header, msg]));
    });

    socket.on("data", (chunk: Buffer) => {
      responseBuffer = Buffer.concat([responseBuffer, chunk]);

      if (expectedLength === null && responseBuffer.length >= 4) {
        expectedLength = responseBuffer.readUInt32BE(0);
        responseBuffer = responseBuffer.subarray(4);
      }

      if (expectedLength !== null && responseBuffer.length >= expectedLength) {
        const data = responseBuffer.subarray(0, expectedLength).toString("utf-8");
        socket.destroy();
        try {
          const response = JSON.parse(data);
          if (!response.ok) {
            reject(new RootAgentError(response.error || "Unknown error"));
          } else {
            resolve(response);
          }
        } catch (e) {
          reject(new RootAgentError(`Invalid response: ${e}`));
        }
      }
    });

    socket.on("error", (err) => {
      socket.destroy();
      reject(new RootAgentError(`Socket error: ${err.message}`));
    });

    socket.on("timeout", () => {
      socket.destroy();
      reject(new RootAgentError("Root agent timeout"));
    });
  });
}

// --- Convenience wrappers ---

export async function iptablesOpen(
  port: number,
  proto = "tcp",
  comment = "blockhost-knock",
  source?: string,
): Promise<void> {
  const params: Record<string, unknown> = { port, proto, comment };
  if (source) params.source = source;
  await callRootAgent("iptables-open", params);
}

export async function iptablesClose(
  port: number,
  proto = "tcp",
  comment = "blockhost-knock",
  source?: string,
): Promise<void> {
  const params: Record<string, unknown> = { port, proto, comment };
  if (source) params.source = source;
  await callRootAgent("iptables-close", params);
}

export async function generateWallet(name: string): Promise<{ address: string }> {
  const result = await callRootAgent("generate-wallet", { name });
  const address = result.address;
  if (typeof address !== "string" || address.length === 0) {
    throw new RootAgentError(
      `generate-wallet returned invalid address: ${String(address)}`,
    );
  }
  return { address };
}

export async function addressbookSave(entries: Record<string, unknown>): Promise<void> {
  await callRootAgent("addressbook-save", { entries });
}
