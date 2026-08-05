import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { createAccount, createClient } = require("../frontend/node_modules/genlayer-js/dist/index.cjs");
const { studionet } = require("../frontend/node_modules/genlayer-js/dist/chains/index.cjs");
const { ExecutionResult, TransactionStatus } = require("../frontend/node_modules/genlayer-js/dist/types/index.cjs");

const pk = process.env.GENLAYER_PRIVATE_KEY;
if (!pk) throw new Error("Set GENLAYER_PRIVATE_KEY in the process environment.");

const account = createAccount(pk.startsWith("0x") ? pk : `0x${pk}`);
const client = createClient({ chain: studionet, account });
const code = fs.readFileSync(path.join(process.cwd(), "backend", "organic-cert.py"), "utf8");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function get(obj, key) {
  if (!obj) return undefined;
  if (obj instanceof Map) return obj.get(key);
  return obj[key];
}

function asNum(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

async function wait(hash, label) {
  console.log(`${label}_tx=${hash}`);
  const receipt = await client.waitForTransactionReceipt({
    hash,
    status: TransactionStatus.ACCEPTED,
    interval: 5000,
    retries: 80,
  });
  console.log(`${label}_status=${receipt.statusName ?? receipt.status}`);
  const leaderResult = receipt.consensus_data?.leader_receipt?.[0]?.execution_result;
  const ok =
    receipt.txExecutionResultName === ExecutionResult.FINISHED_WITH_RETURN ||
    leaderResult === "SUCCESS" ||
    receipt.execution_result === "SUCCESS";
  if (leaderResult === "ERROR" || receipt.txExecutionResultName === ExecutionResult.FINISHED_WITH_ERROR) {
    throw new Error(`${label} rolled back: ${hash}`);
  }
  if ((leaderResult || receipt.execution_result || receipt.txExecutionResultName) && !ok) {
    throw new Error(`${label} did not execute successfully: ${hash}`);
  }
  return receipt;
}

async function write(address, name, args = []) {
  const hash = await client.writeContract({ address, functionName: name, args, value: 0n });
  await wait(hash, name);
  await sleep(2500);
  return hash;
}

async function read(address, name, args = []) {
  return await client.readContract({ address, functionName: name, args });
}

function deploymentAddress(receipt) {
  const direct =
    get(receipt, "contractAddress") ||
    get(receipt, "contract_address") ||
    get(receipt, "recipient") ||
    get(receipt, "to_address");
  if (typeof direct === "string" && /^0x[0-9a-fA-F]{40}$/.test(direct)) return direct;
  const decoded = get(receipt, "decodedData") || get(receipt, "decoded_data") || get(receipt, "data");
  const nested =
    get(decoded, "contractAddress") ||
    get(decoded, "contract_address") ||
    get(decoded, "address");
  if (typeof nested === "string" && /^0x[0-9a-fA-F]{40}$/.test(nested)) return nested;
  throw new Error(`Could not find deployment address in receipt: ${JSON.stringify(receipt).slice(0, 1200)}`);
}

async function main() {
  console.log(`account=${account.address}`);

  const deployHash = await client.deployContract({ code, args: [] });
  const deployReceipt = await wait(deployHash, "deploy");
  const address = deploymentAddress(deployReceipt);
  console.log(`contract=${address}`);

  await write(address, "authorize_evidence_origin", ["https://postman-echo.com", true]);

  const stamp = Date.now().toString(36);
  const farmUrl =
    `https://postman-echo.com/get?cert_status=active&lab=residue_clear&records=complete&lot=${stamp}`;
  const childUrl =
    `https://postman-echo.com/get?cert_status=active&lab=residue_clear&records=plot_complete&lot=${stamp}-plot`;

  await write(address, "submit_farm", [
    `Live Organic Farm ${stamp}`,
    "Leafy greens",
    farmUrl,
    "Claimant note only; authoritative data is fetched from postman-echo for live test.",
  ]);
  await write(address, "run_inspection", [0]);
  await write(address, "issue_badge", [0]);
  const root = await read(address, "get_node_card", [0]);
  console.log(`root_state=${get(root, "state")}`);
  console.log(`root_opinion=${get(root, "opinion")}`);

  await write(address, "add_child", [
    0,
    2,
    "Live north plot",
    childUrl,
    "Child context only.",
  ]);
  await write(address, "run_inspection", [1]);
  await write(address, "issue_badge", [1]);
  await write(address, "suspend_node", [0, "live cascade hold"]);
  const suspended = await read(address, "get_subtree", [0]);
  console.log(`subtree_after_suspend=${JSON.stringify(suspended)}`);
  await write(address, "reinstate_node", [0]);
  await write(address, "revoke_node", [0, "live origin revocation"]);
  const finalTree = await read(address, "get_subtree", [0]);
  const logs = await read(address, "get_cascade_logs", [0, 10]);
  console.log(`final_tree=${JSON.stringify(finalTree)}`);
  console.log(`cascade_logs=${JSON.stringify(logs)}`);
  console.log(`stats=${JSON.stringify(await read(address, "cert_stats"))}`);

  if (asNum(get(await read(address, "cert_stats"), "next_node_id")) < 2) {
    throw new Error("Live test did not create both root and child nodes.");
  }

  // Clean deployment for the UI: authorized origin only, no node/test data.
  const cleanHash = await client.deployContract({ code, args: [] });
  const cleanReceipt = await wait(cleanHash, "clean_deploy");
  const cleanAddress = deploymentAddress(cleanReceipt);
  console.log(`clean_contract=${cleanAddress}`);
  await write(cleanAddress, "authorize_evidence_origin", ["https://postman-echo.com", true]);
  const cleanStats = await read(cleanAddress, "cert_stats");
  console.log(`clean_stats=${JSON.stringify(cleanStats)}`);
  if (asNum(get(cleanStats, "next_node_id")) !== 0) {
    throw new Error("Clean deployment should not contain test nodes.");
  }
}

main().catch((err) => {
  console.error(err?.stack || err);
  process.exit(1);
});
