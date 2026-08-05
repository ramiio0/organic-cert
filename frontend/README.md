# Furrow frontend

Furrow is the Organic-Cert client. It connects RainbowKit/wagmi to `genlayer-js`, so write calls are signed by the connected wallet and sent to the deployed Organic-Cert contract on StudioNet.

## Contract

- Network: GenLayer StudioNet
- Address: `0x4D244C46acEb008EF2b3Bf2F9db2d811F05B9391`

## Flows in the UI

- authorize a certifier/lab evidence origin;
- submit a farm with an authority evidence URL;
- run consensus inspection and issue a badge;
- add downstream nodes under eligible ancestors;
- suspend, reinstate, and revoke subtrees;
- read the tree, origins, stats, transaction links, and cascade log.

## Develop

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
```

