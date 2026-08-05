import { createClient, createAccount } from "genlayer-js";
import { studionet } from "genlayer-js/chains";
import { ExecutionResult, TransactionStatus } from "genlayer-js/types";
import type { WalletClient } from "viem";
import { CONTRACT_ADDRESS, GENLAYER_NETWORK } from "./chain";

type Hex = `0x${string}`;
type WalletProvider = {
  request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
};
export type ConnectedWallet = WalletClient & {
  account: NonNullable<WalletClient["account"]>;
  transport: WalletClient["transport"] & WalletProvider;
};

const ADDR = CONTRACT_ADDRESS as Hex;
const TX_TIMEOUT_MS = 300_000;

export type NodeKindName = "FARM" | "PLOT" | "BATCH" | "PROCESSOR" | "DISTRIBUTOR";

export interface CertInput {
  farmName: string;
  produceDesc: string;
  evidenceUrl: string;
  claimantNote: string;
}

export interface ChildInput {
  parentId: number;
  kindId: number;
  label: string;
  evidenceUrl: string;
  claimantNote: string;
}

export interface CertViolation {
  category: string;
  severity: number;
  note: string;
}

export interface NodeCard {
  nodeId: number;
  parentId: number;
  farmRootId: number;
  holder: string;
  kind: NodeKindName | string;
  label: string;
  farmRef: string;
  evidenceUrl: string;
  evidenceOrigin: string;
  evidenceHash: string;
  evidenceSnapshot: string;
  state: string;
  opinion: string;
  violationCount: number;
  inheritedViolationCount: number;
  severityTotal: number;
  maxSeverity: number;
  categoryMask: number;
  badgeLabel: string;
  depth: number;
  childrenCount: number;
  rationale: string;
}

export interface TreeNode {
  nodeId: number;
  parentId: number;
  kind: string;
  label: string;
  state: string;
  opinion: string;
  depth: number;
  violationCount: number;
  maxSeverity: number;
  childrenCount: number;
}

export interface CascadeLog {
  seq: number;
  triggeringNodeId: number;
  affectedNodeId: number;
  stateFrom: string;
  stateTo: string;
  note: string;
}

export interface OriginRow {
  origin: string;
  authorized: boolean;
}

export interface CertStats {
  nextNodeId: number;
  nextViolationId: number;
  nextSeq: number;
  submittedCount: number;
  badgedCount: number;
  revokedCount: number;
  originCount: number;
}

export interface CertResult {
  card: NodeCard;
  violations: CertViolation[];
  tree: TreeNode[];
  txs: string[];
}

let _read: ReturnType<typeof createClient> | null = null;

function readClient() {
  if (!_read) _read = createClient({ chain: studionet, account: createAccount() });
  return _read;
}

function requireWallet(wallet: WalletClient | undefined): ConnectedWallet {
  if (!wallet?.account?.address) {
    throw new Error("Connect a wallet before sending a transaction.");
  }
  if (typeof wallet.transport?.request !== "function") {
    throw new Error("The connected wallet does not expose a request signer.");
  }
  return wallet as ConnectedWallet;
}

function writeClient(wallet: WalletClient | undefined) {
  const signer = requireWallet(wallet);
  return createClient({
    chain: studionet,
    account: signer.account.address as Hex,
    provider: {
      request: (args: { method: string; params?: unknown[] }) =>
        signer.transport.request(args),
    },
  });
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function get(rec: any, key: string): any {
  if (rec == null) return undefined;
  if (rec instanceof Map) return rec.get(key);
  if (typeof rec === "object" && key in rec) return rec[key];
  return undefined;
}

function num(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function originOf(url: string): string {
  return new URL(url).origin;
}

function shortId(): string {
  return (
    Date.now().toString(36) + Math.random().toString(36).slice(2, 7)
  ).slice(-11);
}

async function readView(functionName: string, args: any[] = []): Promise<any> {
  return await readClient().readContract({ address: ADDR, functionName, args });
}

async function waitAccepted(client: any, hash: Hex) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("Transaction timed out")), TX_TIMEOUT_MS);
  });
  try {
    const receipt: any = await Promise.race([
      client.waitForTransactionReceipt({
        hash,
        status: TransactionStatus.ACCEPTED,
        interval: 5000,
        retries: 60,
      }),
      timeout,
    ]);
    const leaderResult = receipt?.consensus_data?.leader_receipt?.[0]?.execution_result;
    const ok =
      receipt?.txExecutionResultName === ExecutionResult.FINISHED_WITH_RETURN ||
      leaderResult === "SUCCESS" ||
      receipt?.execution_result === "SUCCESS";
    if (leaderResult === "ERROR" || receipt?.txExecutionResultName === ExecutionResult.FINISHED_WITH_ERROR) {
      throw new Error(`Transaction rolled back: ${hash}`);
    }
    if (leaderResult || receipt?.execution_result || receipt?.txExecutionResultName) {
      if (!ok) throw new Error(`Transaction did not execute successfully: ${hash}`);
    }
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function sendTx(
  wallet: WalletClient | undefined,
  functionName: string,
  args: any[]
): Promise<string> {
  const client = writeClient(wallet);
  await client.connect(GENLAYER_NETWORK);
  const hash = (await client.writeContract({
    address: ADDR,
    functionName,
    args,
    value: 0n,
  })) as Hex;
  await waitAccepted(client, hash);
  return String(hash);
}

function toCard(raw: any): NodeCard {
  return {
    nodeId: num(get(raw, "node_id")),
    parentId: num(get(raw, "parent_id")),
    farmRootId: num(get(raw, "farm_root_id")),
    holder: String(get(raw, "holder") ?? ""),
    kind: String(get(raw, "kind") ?? ""),
    label: String(get(raw, "label") ?? ""),
    farmRef: String(get(raw, "farm_ref") ?? ""),
    evidenceUrl: String(get(raw, "evidence_url") ?? ""),
    evidenceOrigin: String(get(raw, "evidence_origin") ?? ""),
    evidenceHash: String(get(raw, "evidence_hash") ?? ""),
    evidenceSnapshot: String(get(raw, "evidence_snapshot") ?? ""),
    state: String(get(raw, "state") ?? ""),
    opinion: String(get(raw, "opinion") ?? ""),
    violationCount: num(get(raw, "violation_count")),
    inheritedViolationCount: num(get(raw, "inherited_violation_count")),
    severityTotal: num(get(raw, "severity_total")),
    maxSeverity: num(get(raw, "max_severity")),
    categoryMask: num(get(raw, "category_mask")),
    badgeLabel: String(get(raw, "badge_label") ?? ""),
    depth: num(get(raw, "depth")),
    childrenCount: num(get(raw, "children_count")),
    rationale: String(get(raw, "rationale") ?? ""),
  };
}

function toTree(raw: any[]): TreeNode[] {
  return (Array.isArray(raw) ? raw : []).map((row) => ({
    nodeId: num(get(row, "node_id")),
    parentId: num(get(row, "parent_id")),
    kind: String(get(row, "kind") ?? ""),
    label: String(get(row, "label") ?? ""),
    state: String(get(row, "state") ?? ""),
    opinion: String(get(row, "opinion") ?? ""),
    depth: num(get(row, "depth")),
    violationCount: num(get(row, "violation_count")),
    maxSeverity: num(get(row, "max_severity")),
    childrenCount: num(get(row, "children_count")),
  }));
}

export async function getCard(nodeId: number): Promise<NodeCard> {
  return toCard(await readView("get_node_card", [nodeId]));
}

export async function getViolations(nodeId: number): Promise<CertViolation[]> {
  const raw = await readView("get_node_violations", [nodeId]);
  return (Array.isArray(raw) ? raw : []).map((v) => ({
    category: String(get(v, "category") ?? "UNKNOWN"),
    severity: num(get(v, "severity")),
    note: String(get(v, "note") ?? ""),
  }));
}

export async function getTree(rootId: number): Promise<TreeNode[]> {
  return toTree(await readView("get_subtree", [rootId]));
}

export async function getLogs(): Promise<CascadeLog[]> {
  const raw = await readView("get_cascade_logs", [0, 25]);
  return (Array.isArray(raw) ? raw : []).map((row) => ({
    seq: num(get(row, "seq")),
    triggeringNodeId: num(get(row, "triggering_node_id")),
    affectedNodeId: num(get(row, "affected_node_id")),
    stateFrom: String(get(row, "state_from") ?? ""),
    stateTo: String(get(row, "state_to") ?? ""),
    note: String(get(row, "note") ?? ""),
  }));
}

export async function getOrigins(): Promise<OriginRow[]> {
  const raw = await readView("get_evidence_origins");
  return (Array.isArray(raw) ? raw : []).map((row) => ({
    origin: String(get(row, "origin") ?? ""),
    authorized: Boolean(get(row, "authorized")),
  }));
}

export async function getStats(): Promise<CertStats> {
  const raw = await readView("cert_stats");
  return {
    nextNodeId: num(get(raw, "next_node_id")),
    nextViolationId: num(get(raw, "next_violation_id")),
    nextSeq: num(get(raw, "next_seq")),
    submittedCount: num(get(raw, "submitted_count")),
    badgedCount: num(get(raw, "badged_count")),
    revokedCount: num(get(raw, "revoked_count")),
    originCount: num(get(raw, "origin_count")),
  };
}

async function pollCard(nodeId: number, ok: (card: NodeCard) => boolean, tries = 18) {
  let card = await getCard(nodeId);
  for (let i = 0; i < tries; i++) {
    if (ok(card)) return card;
    await sleep(4000);
    card = await getCard(nodeId);
  }
  return card;
}

export async function authorizeOrigin(wallet: WalletClient | undefined, origin: string) {
  return await sendTx(wallet, "authorize_evidence_origin", [origin, true]);
}

export async function submitInspectBadge(
  wallet: WalletClient | undefined,
  input: CertInput
): Promise<CertResult> {
  const farmRef = `${(input.farmName.trim() || "Farm").slice(0, 76)} #${shortId()}`;
  const label = input.produceDesc.trim().slice(0, 90) || "Organic lot";
  const note =
    input.claimantNote.trim() ||
    "Claimant context only; final certification must come from fetched certifier or lab evidence.";
  const txs: string[] = [];

  txs.push(await sendTx(wallet, "submit_farm", [farmRef, label, input.evidenceUrl.trim(), note]));
  let nodeId = -1;
  for (let i = 0; i < 12; i++) {
    const resolved = await readView("resolve_farm_node", [farmRef]);
    if (Boolean(get(resolved, "exists"))) {
      nodeId = num(get(resolved, "node_id"));
      break;
    }
    await sleep(3500);
  }
  if (nodeId < 0) throw new Error("The new farm was submitted, but the register did not resolve it yet.");

  txs.push(await sendTx(wallet, "run_inspection", [nodeId]));
  let card = await pollCard(nodeId, (c) => c.state !== "SUBMITTED");

  if (card.opinion === "CERTIFIED" || card.opinion === "CONDITIONAL") {
    txs.push(await sendTx(wallet, "issue_badge", [nodeId]));
    card = await pollCard(nodeId, (c) => c.state === "BADGED");
  }

  return {
    card,
    violations: await getViolations(nodeId),
    tree: await getTree(card.farmRootId),
    txs,
  };
}

export async function addChildNode(wallet: WalletClient | undefined, input: ChildInput) {
  return await sendTx(wallet, "add_child", [
    input.parentId,
    input.kindId,
    input.label.trim(),
    input.evidenceUrl.trim(),
    input.claimantNote.trim(),
  ]);
}

export async function inspectNode(wallet: WalletClient | undefined, nodeId: number) {
  return await sendTx(wallet, "run_inspection", [nodeId]);
}

export async function issueBadge(wallet: WalletClient | undefined, nodeId: number) {
  return await sendTx(wallet, "issue_badge", [nodeId]);
}

export async function suspendNode(wallet: WalletClient | undefined, nodeId: number, reason: string) {
  return await sendTx(wallet, "suspend_node", [nodeId, reason]);
}

export async function reinstateNode(wallet: WalletClient | undefined, nodeId: number) {
  return await sendTx(wallet, "reinstate_node", [nodeId]);
}

export async function revokeNode(wallet: WalletClient | undefined, nodeId: number, reason: string) {
  return await sendTx(wallet, "revoke_node", [nodeId, reason]);
}

export function evidenceOrigin(url: string): string {
  try {
    return originOf(url.trim());
  } catch {
    return "";
  }
}
