import { defineChain } from "viem";

// GenLayer StudioNet.
export const GENLAYER_CHAIN_ID = 61999;
export const GENLAYER_RPC_URL = "https://studio.genlayer.com/api";
export const GENLAYER_EXPLORER_URL = "https://explorer-studio.genlayer.com";

// Updated after the clean StudioNet deployment.
export const CONTRACT_ADDRESS =
  "0x4D244C46acEb008EF2b3Bf2F9db2d811F05B9391" as const;

export const GENLAYER_NETWORK = "studionet" as const;

export const genLayerStudioNet = defineChain({
  id: GENLAYER_CHAIN_ID,
  name: "GenLayer StudioNet",
  nativeCurrency: { name: "GEN", symbol: "GEN", decimals: 18 },
  rpcUrls: {
    default: { http: [GENLAYER_RPC_URL] },
    public: { http: [GENLAYER_RPC_URL] },
  },
  blockExplorers: {
    default: { name: "GenLayer Explorer", url: GENLAYER_EXPLORER_URL },
  },
  testnet: true,
});
