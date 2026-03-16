/**
 * Provisioner manifest reader — discovers active provisioner's commands.
 * Falls back to legacy hardcoded names when no manifest exists.
 */

import * as fs from "fs";

const MANIFEST_PATH = "/usr/share/blockhost/provisioner.json";

const LEGACY_COMMANDS: Record<string, string> = {
  create:           "blockhost-vm-create",
  destroy:          "blockhost-vm-destroy",
  start:            "blockhost-vm-start",
  stop:             "blockhost-vm-stop",
  kill:             "blockhost-vm-kill",
  status:           "blockhost-vm-status",
  list:             "blockhost-vm-list",
  metrics:          "blockhost-vm-metrics",
  throttle:         "blockhost-vm-throttle",
  "build-template": "blockhost-build-template",
  gc:               "blockhost-vm-gc",
  resume:           "blockhost-vm-resume",
  "update-gecos":   "blockhost-vm-update-gecos",
};

interface ProvisionerManifest {
  name: string;
  version: string;
  display_name: string;
  commands: Record<string, string>;
  setup?: {
    first_boot_hook?: string;
    detect?: string;
    wizard_module?: string;
    finalization_steps?: string[];
  };
}

let _manifest: ProvisionerManifest | null = null;
let _loaded = false;

function loadManifest(): ProvisionerManifest | null {
  if (_loaded) return _manifest;
  _loaded = true;

  try {
    if (fs.existsSync(MANIFEST_PATH)) {
      _manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
      console.log(`[INFO] Loaded provisioner manifest: ${_manifest!.display_name} v${_manifest!.version}`);
      return _manifest;
    }
  } catch (err) {
    console.warn(`[WARN] Failed to load provisioner manifest: ${err}`);
  }

  return null;
}

export function getCommand(verb: string): string {
  const manifest = loadManifest();
  const commands = manifest?.commands ?? LEGACY_COMMANDS;
  const cmd = commands[verb];
  if (!cmd) {
    throw new Error(`Unknown provisioner command: ${verb}`);
  }
  return cmd;
}
