# Organic-Cert StudioNet on-chain test evidence

## Final clean deployment

- Network: GenLayer StudioNet
- Contract: `0x4D244C46acEb008EF2b3Bf2F9db2d811F05B9391`
- Deployer: `0x9D377ce0F810BE2EFCd416364a01c2a89a12F2C5`
- Clean deploy TX: `0xb1dbeea1910ce1ece1ace8f6c54283552fb7ab16b450b80bb3907b6c00d1554d`
- Clean authorized-origin TX: `0x5665e593b5dda98346e68f3570c40124bcbb0e2fbfd570c35e4b4b2a48d32c1b`
- Clean state: `next_node_id=0`, `badged_count=0`, `revoked_count=0`, `origin_count=1`

The frontend points to this clean contract so the submitted UI is not preloaded with test nodes.

## Live lifecycle smoke deployment

- Test contract: `0x2F07F587D780DB2feC430Fa4ad8653b5cbF04853`
- Deploy TX: `0x7d01a8db35fa14f407bd54a001c5707d066c0ec87d0e95797a13067f61dda337`

Transactions executed:

| Function | TX |
|---|---|
| `authorize_evidence_origin` | `0x26979fc8321df9a2eafafbbd8ca984a3b7849b995366454816d507edefba0bc2` |
| `submit_farm` | `0x7800f23ae65a9195762f914f6130c4b384686c1ca8675647c14551264f7cd7bd` |
| `run_inspection` root | `0x7990429fbdeaa65444f4505daec0cbbb50309e65054d324b08613db7e6626eb4` |
| `issue_badge` root | `0xad3784c9d250eb435f5b273584a752b1098d9f51fe6fb9ada06bec0783afeaa7` |
| `add_child` | `0x83063ca93246e91d1c287fc0eef8f7fd697a37facc66545a319298319bb7ff22` |
| `run_inspection` child | `0x40d7f47cc9834e884d8b39050e2047fa1cb19c12a35204f57e58a67a289612c7` |
| `issue_badge` child | `0xd9b2d079f73aa63b00caac02478485f5a72802073ee1086e287688d9312755df` |
| `suspend_node` root cascade | `0x2440b9d550eeaad6a48f86d04f9190f66a4e2d2c7da6fc930ff914907da8d6f1` |
| `reinstate_node` root subtree | `0x98f7af5163f39d083c15003ca5add208f592491e1940e209221e696d285b1238` |
| `revoke_node` root cascade | `0x4705a1592372daffdbd055b0abf03e8291b85d113ea31b19bf34242ce96f89ef` |

Final smoke assertions:

- Root was inspected from fetched certifier/lab evidence and badged as `CERTIFIED`.
- Child could only be added under an eligible badged ancestor.
- Suspending the root cascaded the child to `CASCADED`.
- Reinstating the root reinstated the subtree.
- Revoking the root set the root to `REVOKED` and child to `CASCADED`.
- Cascade log recorded all affected nodes and transitions.
- Final smoke stats: `next_node_id=2`, `badged_count=2`, `revoked_count=1`.
