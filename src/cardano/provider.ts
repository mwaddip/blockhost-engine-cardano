/**
 * Chain query provider — re-exports from cmttk.
 *
 * The provider interface, implementations (Koios, Blockfrost), and factory
 * (getProvider / resetProvider) live in the cmttk package.  All consumers
 * use CardanoProvider directly.
 */

export { getProvider, resetProvider } from "cmttk";
export type { CardanoProvider, ProtocolParams } from "cmttk";
