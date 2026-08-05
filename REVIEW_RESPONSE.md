# Organic-Cert response

## Fix implemented

Organic-Cert no longer treats claimant-written dossier text as authoritative proof.

- Validators fetch certifier/lab evidence from an authorized HTTPS origin using `gl.nondet.web`.
- Evidence origins are owner-authorized with `authorize_evidence_origin`.
- Evidence URLs are unique, preventing reuse of the same authority record across nodes.
- Inspection consensus must agree on:
  - violation categories;
  - severity;
  - violation count;
  - final opinion.
- The final opinion is derived from severity/count rather than claimant text.
- Child nodes require an eligible ancestor chain before they can be added or badged.
- Suspension and revocation cascade consistently through descendants.
- Reinstatement walks the subtree and respects ancestor eligibility.

## Integrated client

The React client exposes the full workflow:

- authorize certifier/lab evidence origin;
- submit a farm with an authority evidence URL;
- inspect and issue badge;
- add downstream child nodes;
- view tree/subtree/ancestors;
- suspend, reinstate, and revoke with cascade log visible.

Writes use the connected RainbowKit/wagmi wallet signer and `genlayer-js`.

## Verification

- GenVM lint: PASS
- Direct tests: 4/4 PASS
- Frontend production build: PASS
- StudioNet live lifecycle smoke: PASS

## Final clean deployment

- Network: GenLayer StudioNet
- Contract: `0x4D244C46acEb008EF2b3Bf2F9db2d811F05B9391`
- Clean deploy TX: `0xb1dbeea1910ce1ece1ace8f6c54283552fb7ab16b450b80bb3907b6c00d1554d`
- Clean authorized-origin TX: `0x5665e593b5dda98346e68f3570c40124bcbb0e2fbfd570c35e4b4b2a48d32c1b`
