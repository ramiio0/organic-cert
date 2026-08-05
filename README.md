# Organic-Cert

Organic-Cert is a GenLayer supply-chain registry for organic certification. It models a certified claim as a tree: a root farm, then downstream plots, batches, processors, or distributors. Each node carries its own authority evidence and inherits the eligibility of its ancestors.

The important design choice is that claimant text is not treated as proof. A node must point to an authorized HTTPS origin controlled by a certifier, lab, registry, or audit authority. During inspection, GenLayer validators fetch that evidence with `gl.nondet.web`, then use consensus to agree on violation categories, severity, and the final organic opinion.

## What the contract enforces

- Owner-controlled evidence origins through `authorize_evidence_origin`.
- Unique authority evidence URLs, so the same lab/certifier page cannot be reused for multiple nodes.
- Root farm submission with `submit_farm(farm_ref, label, evidence_url, claimant_note)`.
- Downstream node creation with `add_child(parent_id, kind, label, evidence_url, claimant_note)`.
- Ancestor eligibility: children can only be added or inspected under a badged, non-failed parent chain.
- Consensus inspection that returns categories, per-finding severity, max severity, and a deterministic opinion.
- Badge issuance only for `CERTIFIED` or `CONDITIONAL` nodes.
- Cascading suspension and revocation across the full subtree.
- Reinstatement workflow for suspended/cascaded nodes.

## Contract views

The app and tests use these views to keep the registry auditable:

- `get_node_card(node_id)`
- `get_node_violations(node_id)`
- `get_children(parent_id)`
- `get_subtree(root_id)`
- `get_ancestors(node_id)`
- `get_cascade_logs(offset, limit)`
- `get_evidence_origins()`
- `cert_stats()`
- distribution helpers for state, opinion, kind, and violation categories

## Integrated client

The React client is wired to GenLayer StudioNet with RainbowKit/wagmi. Writes are sent through the connected wallet signer, then passed into `genlayer-js` using the wallet provider. The UI exposes the full lifecycle:

1. authorize an evidence origin;
2. register a farm from a certifier/lab URL;
3. run inspection and issue a badge;
4. add downstream nodes;
5. inspect/badge selected nodes;
6. suspend, reinstate, or revoke a subtree;
7. read the live tree and cascade log from contract views.

## StudioNet deployment

- Network: GenLayer StudioNet
- Contract: `0x4D244C46acEb008EF2b3Bf2F9db2d811F05B9391`
- Explorer: `https://explorer-studio.genlayer.com/address/0x4D244C46acEb008EF2b3Bf2F9db2d811F05B9391`

The deployed client points at the clean contract above. It has no submitted farm nodes by default; only the demo evidence origin `https://postman-echo.com` is authorized so the UI can be exercised immediately.

## Local development

```bash
cd frontend
npm install
npm run build
npm run dev
```

Direct contract tests:

```bash
python -m pytest tests/direct -q
```

GenVM lint:

```bash
genvm-lint check backend/organic-cert.py --json
```

StudioNet live test, with a private key supplied only as a process environment variable:

```bash
GENLAYER_PRIVATE_KEY=... node scripts/studionet-live-test.mjs
```

## Repository layout

```text
backend/
  organic-cert.py          GenLayer intelligent contract
frontend/
  src/
    App.tsx                Supply-chain workflow UI
    contractService.ts     genlayer-js read/write client
    chain.ts               StudioNet config and contract address
tests/
  direct/
    test_organic_cert.py   Fast direct tests for authority, tree, and cascade paths
  scripts/
  studionet-live-test.mjs  Deployment and on-chain lifecycle smoke test
```

Live: https://ramiio0.github.io/organic-cert/

