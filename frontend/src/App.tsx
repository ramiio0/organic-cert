import { useEffect, useRef, useState } from "react";
import { ConnectButton } from "@rainbow-me/rainbowkit";
import { useAccount, useWalletClient } from "wagmi";
import anime from "animejs";
import {
  addChildNode,
  authorizeOrigin,
  CertResult,
  CertStats,
  CascadeLog,
  evidenceOrigin,
  getLogs,
  getOrigins,
  getStats,
  getTree,
  inspectNode,
  issueBadge,
  NodeCard,
  OriginRow,
  reinstateNode,
  revokeNode,
  submitInspectBadge,
  suspendNode,
  TreeNode,
} from "./contractService";
import { CONTRACT_ADDRESS, GENLAYER_EXPLORER_URL } from "./chain";

function WalletControl() {
  return (
    <ConnectButton.Custom>
      {({ account, chain, openAccountModal, openChainModal, openConnectModal, mounted }) => {
        const connected = mounted && account && chain;
        if (!connected)
          return (
            <button className="wbtn" onClick={openConnectModal} type="button">
              Connect Wallet
            </button>
          );
        if (chain?.unsupported)
          return (
            <button className="wbtn wbtn-warn" onClick={openChainModal} type="button">
              Wrong network
            </button>
          );
        return (
          <button className="wchip" onClick={openAccountModal} type="button">
            <span className="wdot" />
            {account.displayName}
          </button>
        );
      }}
    </ConnectButton.Custom>
  );
}

const PRODUCE = [
  "Heirloom tomatoes",
  "Stone fruit",
  "Leafy greens",
  "Table grapes",
  "Tree nuts",
  "Root vegetables",
];

const CHILD_KINDS = [
  { id: 2, label: "PLOT" },
  { id: 3, label: "BATCH" },
  { id: 4, label: "PROCESSOR" },
  { id: 5, label: "DISTRIBUTOR" },
];

const RINGS = [128, 100, 74];

function ringFraction(v: string): number {
  if (v === "CERTIFIED") return 1;
  if (v === "CONDITIONAL") return 0.62;
  if (v === "FAILED") return 0.34;
  return 0;
}

function Seal({ verdict, badge }: { verdict: string; badge: boolean }) {
  const ref = useRef<SVGSVGElement>(null);
  const frac = ringFraction(verdict);
  const rings = RINGS.map((r) => {
    const c = 2 * Math.PI * r;
    return { r, c, target: c * (1 - frac) };
  });
  const strikeLen = Math.sqrt(2) * 256;

  useEffect(() => {
    const svg = ref.current;
    if (!svg) return;
    const reduce =
      typeof window !== "undefined" &&
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const ringEls = svg.querySelectorAll<SVGCircleElement>(".seal-ring");
    const strikeEl = svg.querySelector<SVGLineElement>(".seal-strike");

    if (!verdict) {
      ringEls.forEach((el) => {
        el.style.strokeDashoffset = el.getAttribute("data-circ") || "0";
      });
      if (strikeEl) strikeEl.style.strokeDashoffset = String(strikeLen);
      return;
    }

    if (reduce) {
      ringEls.forEach((el) => {
        el.style.strokeDashoffset = el.getAttribute("data-target") || "0";
      });
      if (strikeEl) strikeEl.style.strokeDashoffset = "0";
      return;
    }

    const anims: any[] = [];
    anims.push(
      anime({
        targets: ringEls,
        strokeDashoffset: [
          (el: any) => el.getAttribute("data-circ"),
          (el: any) => el.getAttribute("data-target"),
        ],
        duration: 1100,
        delay: anime.stagger(180),
        easing: "easeInOutSine",
      })
    );
    if (strikeEl && verdict === "FAILED") {
      strikeEl.style.strokeDashoffset = String(strikeLen);
      anims.push(
        anime({
          targets: strikeEl,
          strokeDashoffset: [strikeLen, 0],
          duration: 520,
          delay: 760,
          easing: "easeOutExpo",
        })
      );
    }
    return () => anims.forEach((a) => a.pause());
  }, [verdict, strikeLen]);

  return (
    <svg
      ref={ref}
      className={"seal seal-" + (verdict || "idle")}
      viewBox="0 0 320 320"
      role="img"
      aria-label="Certification seal"
    >
      <g className="seal-notches">
        {Array.from({ length: 48 }).map((_, i) => {
          const a = (i / 48) * Math.PI * 2;
          const r1 = 146;
          const r2 = i % 4 === 0 ? 137 : 141;
          return (
            <line
              key={i}
              x1={160 + Math.cos(a) * r1}
              y1={160 + Math.sin(a) * r1}
              x2={160 + Math.cos(a) * r2}
              y2={160 + Math.sin(a) * r2}
            />
          );
        })}
      </g>
      {rings.map((rg, i) => (
        <circle
          key={i}
          className="seal-ring"
          cx={160}
          cy={160}
          r={rg.r}
          data-circ={rg.c}
          data-target={rg.target}
          style={{
            strokeDasharray: rg.c,
            strokeDashoffset: rg.c,
            transform: "rotate(-90deg)",
            transformOrigin: "160px 160px",
          }}
        />
      ))}
      <line
        className="seal-strike"
        x1={70}
        y1={70}
        x2={250}
        y2={250}
        style={{ strokeDasharray: strikeLen, strokeDashoffset: strikeLen }}
      />
      <text className="seal-word" x="160" y="156" textAnchor="middle">
        {verdict || "PENDING"}
      </text>
      <text className="seal-sub" x="160" y="182" textAnchor="middle">
        {verdict ? (badge ? "MARK GRANTED" : "MARK WITHHELD") : "AUTH EVIDENCE"}
      </text>
    </svg>
  );
}

function prettyCat(c: string): string {
  return c
    .toLowerCase()
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

function SeverityBar({ value }: { value: number }) {
  return (
    <span className="sev" aria-label={"Severity " + value + " of 5"}>
      {[1, 2, 3, 4, 5].map((c) => (
        <span key={c} className={"sev-cell" + (c <= value ? " sev-on" : "")} />
      ))}
    </span>
  );
}

function txShort(hash: string) {
  return `${hash.slice(0, 8)}...${hash.slice(-6)}`;
}

function TreeList({ rows }: { rows: TreeNode[] }) {
  if (!rows.length) return <p className="clean-note">No tree loaded yet.</p>;
  return (
    <div className="tree-list">
      {rows.map((row) => (
        <div className="tree-row" key={row.nodeId} style={{ marginLeft: row.depth * 18 }}>
          <span className="tree-id">#{row.nodeId}</span>
          <span className="tree-kind">{row.kind}</span>
          <span className="tree-label">{row.label}</span>
          <span className={"tree-state state-" + row.state}>{row.state}</span>
          <span className="tree-meta">
            {row.opinion} · severity {row.maxSeverity} · children {row.childrenCount}
          </span>
        </div>
      ))}
    </div>
  );
}

export function App() {
  const { isConnected } = useAccount();
  const { data: wallet } = useWalletClient();

  const [farmName, setFarmName] = useState("");
  const [produce, setProduce] = useState("Heirloom tomatoes");
  const [url, setUrl] = useState("");
  const [note, setNote] = useState("");
  const [authOrigin, setAuthOrigin] = useState("https://postman-echo.com");
  const [loading, setLoading] = useState("");
  const [res, setRes] = useState<CertResult | null>(null);
  const [tree, setTree] = useState<TreeNode[]>([]);
  const [logs, setLogs] = useState<CascadeLog[]>([]);
  const [origins, setOrigins] = useState<OriginRow[]>([]);
  const [stats, setStats] = useState<CertStats | null>(null);
  const [selectedId, setSelectedId] = useState(0);
  const [childKind, setChildKind] = useState(2);
  const [childLabel, setChildLabel] = useState("North plot");
  const [childUrl, setChildUrl] = useState("");
  const [childNote, setChildNote] = useState("");
  const [reason, setReason] = useState("temporary certifier hold");
  const [error, setError] = useState("");

  const card: NodeCard | null = res?.card ?? null;
  const verdict = card?.opinion?.toUpperCase() || "";
  const canWrite = isConnected && !!wallet && !loading;
  const detectedOrigin = evidenceOrigin(url);

  async function refresh(rootId = card?.farmRootId ?? selectedId ?? 0) {
    const [o, s, l] = await Promise.all([getOrigins(), getStats(), getLogs()]);
    setOrigins(o);
    setStats(s);
    setLogs(l);
    if (rootId >= 0 && s.nextNodeId > 0) {
      try {
        setTree(await getTree(rootId));
      } catch {
        // root may not exist yet
      }
    }
  }

  useEffect(() => {
    refresh().catch(() => undefined);
    const timer = window.setInterval(() => refresh().catch(() => undefined), 20000);
    return () => window.clearInterval(timer);
  }, []);

  async function act(label: string, fn: () => Promise<void>) {
    setLoading(label);
    setError("");
    try {
      await fn();
      await refresh();
    } catch (e: any) {
      setError(e?.message?.slice(0, 220) || "Transaction failed");
    } finally {
      setLoading("");
    }
  }

  async function onAuthorize() {
    await act("Authorizing origin...", async () => {
      await authorizeOrigin(wallet, authOrigin.trim());
    });
  }

  async function onSubmit() {
    await act("Registering, fetching evidence, and inspecting...", async () => {
      const result = await submitInspectBadge(wallet, {
        farmName,
        produceDesc: produce,
        evidenceUrl: url,
        claimantNote:
          note ||
          "Claimant note only. Contract must fetch certifier or lab evidence before ruling.",
      });
      setRes(result);
      setTree(result.tree);
      setSelectedId(result.card.nodeId);
    });
  }

  async function onAddChild() {
    await act("Adding downstream node...", async () => {
      await addChildNode(wallet, {
        parentId: selectedId,
        kindId: childKind,
        label: childLabel,
        evidenceUrl: childUrl,
        claimantNote: childNote || "Downstream claimant context only.",
      });
    });
  }

  async function lifecycle(kind: "inspect" | "badge" | "suspend" | "reinstate" | "revoke") {
    await act(kind + " node...", async () => {
      if (kind === "inspect") await inspectNode(wallet, selectedId);
      if (kind === "badge") await issueBadge(wallet, selectedId);
      if (kind === "suspend") await suspendNode(wallet, selectedId, reason);
      if (kind === "reinstate") await reinstateNode(wallet, selectedId);
      if (kind === "revoke") await revokeNode(wallet, selectedId, reason);
    });
  }

  const submitReady =
    canWrite &&
    farmName.trim().length >= 2 &&
    produce.trim().length >= 2 &&
    url.trim().startsWith("https://");

  return (
    <div className="paper">
      <header className="masthead">
        <div className="mast-left">
          <h1 className="logo">Furrow</h1>
          <span className="logo-sub">Organic supply-chain registry</span>
        </div>
        <div className="mast-right">
          <span className="dateline">StudioNet · authority evidence</span>
          <WalletControl />
        </div>
      </header>
      <div className="rule-heavy" />
      <p className="standfirst">
        Register a farm, fetch the certifier or lab record directly, let GenLayer validators agree
        on violation categories and severity, then keep every downstream claim tied to its eligible
        ancestors.
      </p>
      <div className="rule-thin" />

      <main className="columns">
        <section className="col col-intake">
          <h2 className="col-h">Authority path</h2>
          <label className="lbl" htmlFor="origin">Authorize evidence origin</label>
          <p className="hint">
            Owner-only. The contract refuses claimant-only evidence unless its HTTPS origin was
            explicitly authorized.
          </p>
          <div className="inline-row">
            <input
              id="origin"
              className="url-in"
              value={authOrigin}
              onChange={(e) => setAuthOrigin(e.target.value)}
              spellCheck={false}
            />
            <button className="mini-btn" disabled={!canWrite} onClick={onAuthorize} type="button">
              Authorize
            </button>
          </div>
          <div className="origins">
            {origins.map((o) => (
              <span className="origin-pill" key={o.origin}>
                {o.authorized ? "✓" : "×"} {o.origin}
              </span>
            ))}
          </div>

          <h2 className="col-h spaced">Register farm</h2>
          <label className="lbl" htmlFor="farm">Farm name</label>
          <input
            id="farm"
            className="short-in"
            value={farmName}
            onChange={(e) => setFarmName(e.target.value)}
            placeholder="Cold Hollow Orchard"
            spellCheck={false}
          />

          <span className="lbl">Produce</span>
          <div className="chips">
            {PRODUCE.map((p) => (
              <button
                key={p}
                type="button"
                className={"chip" + (produce === p ? " chip-on" : "")}
                onClick={() => setProduce(p)}
              >
                {p}
              </button>
            ))}
          </div>

          <label className="lbl" htmlFor="url">Certifier or lab evidence URL</label>
          <input
            id="url"
            className="url-in"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              const o = evidenceOrigin(e.target.value);
              if (o) setAuthOrigin(o);
            }}
            placeholder="https://postman-echo.com/get?cert_status=active"
            spellCheck={false}
            autoComplete="off"
          />
          {detectedOrigin && <p className="hint">Detected origin: {detectedOrigin}</p>}

          <label className="lbl" htmlFor="note">Claimant note</label>
          <textarea
            id="note"
            className="note-in"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Optional context. Validators must still rely on fetched evidence."
          />

          <button className="rule-btn" disabled={!submitReady} onClick={onSubmit}>
            {loading || "Submit · inspect · issue badge"}
          </button>
          {!isConnected && <span className="needwallet">Connect a wallet on StudioNet.</span>}
          {error && <p className="err">{error}</p>}
        </section>

        <section className="col col-feature">
          <div className="seal-frame">
            <Seal verdict={loading ? "" : verdict} badge={card?.state === "BADGED"} />
          </div>
          <p className="feature-cap">
            {loading
              ? "Waiting for signed StudioNet transactions..."
              : card
              ? "The current node's state, drawn from contract views."
              : "The seal opens only after authenticated evidence is fetched."}
          </p>
          {card && (
            <div className="snapshot">
              <span className="stamp-key">Fetched evidence snapshot</span>
              <p>{card.evidenceSnapshot || "No snapshot stored yet."}</p>
            </div>
          )}
        </section>

        <section className="col col-reading">
          <h2 className="col-h">Ruling</h2>
          {card ? (
            <article className={"verdict v-" + verdict}>
              <span className="drop-cap">{verdict.slice(0, 1)}</span>
              <h3 className="v-tag">{card.opinion}</h3>
              {card.badgeLabel && <span className="v-badge">Mark granted</span>}
              <p className="v-note">{card.rationale || "No remarks returned yet."}</p>
              <p className="v-sum">
                Node #{card.nodeId} · {card.kind} · state {card.state} · severity{" "}
                {card.maxSeverity}
              </p>
              <span className="v-foot">Evidence: {card.evidenceOrigin}</span>
            </article>
          ) : (
            <p className="awaiting">
              Submit an authorized evidence URL. The claimant note is stored as context, but the
              ruling comes from the fetched certifier/lab record.
            </p>
          )}
        </section>
      </main>

      <div className="rule-thin" />
      <section className="workflow">
        <div className="workflow-head">
          <h2 className="col-h">Tree and revocation workflow</h2>
          <div className="stats-strip">
            <span>nodes {stats?.nextNodeId ?? 0}</span>
            <span>badges {stats?.badgedCount ?? 0}</span>
            <span>revoked {stats?.revokedCount ?? 0}</span>
            <span>origins {stats?.originCount ?? 0}</span>
          </div>
        </div>

        <div className="workflow-grid">
          <div>
            <label className="lbl" htmlFor="nodeid">Selected node id</label>
            <input
              id="nodeid"
              className="short-in"
              type="number"
              value={selectedId}
              onChange={(e) => setSelectedId(Number(e.target.value))}
            />
            <div className="button-row">
              <button className="mini-btn" disabled={!canWrite} onClick={() => lifecycle("inspect")}>
                Inspect
              </button>
              <button className="mini-btn" disabled={!canWrite} onClick={() => lifecycle("badge")}>
                Badge
              </button>
              <button className="mini-btn" disabled={!canWrite} onClick={() => lifecycle("suspend")}>
                Suspend subtree
              </button>
              <button className="mini-btn" disabled={!canWrite} onClick={() => lifecycle("reinstate")}>
                Reinstate
              </button>
              <button className="mini-btn danger" disabled={!canWrite} onClick={() => lifecycle("revoke")}>
                Revoke cascade
              </button>
            </div>
            <label className="lbl" htmlFor="reason">Workflow reason</label>
            <input
              id="reason"
              className="short-in"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>

          <div>
            <span className="lbl">Add downstream node</span>
            <div className="inline-row">
              <select
                className="select-in"
                value={childKind}
                onChange={(e) => setChildKind(Number(e.target.value))}
              >
                {CHILD_KINDS.map((k) => (
                  <option value={k.id} key={k.id}>
                    {k.label}
                  </option>
                ))}
              </select>
              <input
                className="short-in"
                value={childLabel}
                onChange={(e) => setChildLabel(e.target.value)}
                placeholder="North plot"
              />
            </div>
            <label className="lbl" htmlFor="childurl">Child evidence URL</label>
            <input
              id="childurl"
              className="url-in"
              value={childUrl}
              onChange={(e) => setChildUrl(e.target.value)}
              placeholder="Same authorized origin as parent"
            />
            <label className="lbl" htmlFor="childnote">Child claimant note</label>
            <textarea
              id="childnote"
              className="note-in"
              value={childNote}
              onChange={(e) => setChildNote(e.target.value)}
            />
            <button className="rule-btn small" disabled={!canWrite || !childUrl} onClick={onAddChild}>
              Add child
            </button>
          </div>
        </div>

        <TreeList rows={tree} />
      </section>

      {res && (
        <>
          <div className="rule-thin" />
          <section className="entry">
            <div className="entry-head">
              <h2 className="col-h">Filed entry</h2>
              <span className={"standing standing-" + verdict}>{card?.state || "FILED"}</span>
            </div>
            <div className="entry-grid">
              <div className="fig">
                <span className="fig-num">#{card?.nodeId}</span>
                <span className="fig-lbl">Register no.</span>
              </div>
              <div className="fig">
                <span className="fig-num">{card?.kind}</span>
                <span className="fig-lbl">Entry kind</span>
              </div>
              <div className="fig">
                <span className="fig-num">{card?.violationCount}</span>
                <span className="fig-lbl">Findings</span>
              </div>
              <div className="fig">
                <span className="fig-num">{card?.maxSeverity}</span>
                <span className="fig-lbl">Max severity</span>
              </div>
            </div>

            {card?.badgeLabel && (
              <div className="stamp">
                <span className="stamp-key">Seal of record</span>
                <span className="stamp-val">{card.badgeLabel}</span>
              </div>
            )}

            <h3 className="findings-h">Consensus categories</h3>
            {res.violations.length > 0 ? (
              <ul className="findings">
                {res.violations.map((vio, i) => (
                  <li key={i} className="finding-row">
                    <span className="finding-cat">{prettyCat(vio.category)}</span>
                    <SeverityBar value={vio.severity} />
                    <span className="finding-note">{vio.note || "No remark recorded."}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="clean-note">
                No standard violations were recorded by consensus for this entry.
              </p>
            )}

            <h3 className="findings-h">Signed transaction path</h3>
            <div className="tx-list">
              {res.txs.map((tx) => (
                <a href={`${GENLAYER_EXPLORER_URL}/tx/${tx}`} target="_blank" rel="noreferrer" key={tx}>
                  {txShort(tx)}
                </a>
              ))}
            </div>
          </section>
        </>
      )}

      <div className="rule-thin" />
      <section className="logs">
        <h2 className="col-h">Cascade log</h2>
        {logs.length ? (
          logs.map((log) => (
            <div className="log-row" key={log.seq}>
              #{log.seq} node {log.affectedNodeId}: {log.stateFrom} → {log.stateTo} · {log.note}
            </div>
          ))
        ) : (
          <p className="clean-note">No cascade event yet.</p>
        )}
      </section>

      <div className="rule-thin" />
      <footer className="colophon">
        <span className="colo-mark">Furrow</span>
        <span className="colo-mono">
          Contract {CONTRACT_ADDRESS.slice(0, 6)}...{CONTRACT_ADDRESS.slice(-4)} ·{" "}
          <a href={`${GENLAYER_EXPLORER_URL}/address/${CONTRACT_ADDRESS}`} target="_blank" rel="noreferrer">
            explorer
          </a>{" "}
          · signed writes on GenLayer StudioNet
        </span>
      </footer>
    </div>
  );
}
