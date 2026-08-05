# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import json
import hashlib
from dataclasses import dataclass
from enum import IntEnum
from genlayer import *

try:
    allow_storage
except NameError:
    def allow_storage(cls):
        return cls


class NodeKind(IntEnum):
    FARM = 1
    PLOT = 2
    BATCH = 3


NODE_KIND_NAMES = {
    int(NodeKind.FARM): "FARM",
    int(NodeKind.PLOT): "PLOT",
    int(NodeKind.BATCH): "BATCH",
}


class CertState(IntEnum):
    SUBMITTED = 0
    INSPECTING = 1
    RESOLVED = 2
    BADGED = 3
    SUSPENDED = 4
    REVOKED = 5
    CASCADED = 6


CERT_STATE_NAMES = {
    int(CertState.SUBMITTED): "SUBMITTED",
    int(CertState.INSPECTING): "INSPECTING",
    int(CertState.RESOLVED): "RESOLVED",
    int(CertState.BADGED): "BADGED",
    int(CertState.SUSPENDED): "SUSPENDED",
    int(CertState.REVOKED): "REVOKED",
    int(CertState.CASCADED): "CASCADED",
}


class Opinion(IntEnum):
    PENDING = 0
    CERTIFIED = 1
    CONDITIONAL = 2
    FAILED = 3


OPINION_NAMES = {
    int(Opinion.PENDING): "PENDING",
    int(Opinion.CERTIFIED): "CERTIFIED",
    int(Opinion.CONDITIONAL): "CONDITIONAL",
    int(Opinion.FAILED): "FAILED",
}


class ViolationCategory(IntEnum):
    PESTICIDE_RESIDUE = 1
    NON_COMPLIANT_INPUT = 2
    RECORD_KEEPING = 3
    FORGED_DOC = 4
    BUFFER_ZONE = 5
    PARALLEL_PRODUCTION = 6
    UNKNOWN = 7


VIOLATION_CATEGORY_NAMES = {
    int(ViolationCategory.PESTICIDE_RESIDUE): "PESTICIDE_RESIDUE",
    int(ViolationCategory.NON_COMPLIANT_INPUT): "NON_COMPLIANT_INPUT",
    int(ViolationCategory.RECORD_KEEPING): "RECORD_KEEPING",
    int(ViolationCategory.FORGED_DOC): "FORGED_DOC",
    int(ViolationCategory.BUFFER_ZONE): "BUFFER_ZONE",
    int(ViolationCategory.PARALLEL_PRODUCTION): "PARALLEL_PRODUCTION",
    int(ViolationCategory.UNKNOWN): "UNKNOWN",
}


VIOLATION_SEVERITY = {
    int(ViolationCategory.PESTICIDE_RESIDUE): 5,
    int(ViolationCategory.FORGED_DOC): 5,
    int(ViolationCategory.NON_COMPLIANT_INPUT): 4,
    int(ViolationCategory.PARALLEL_PRODUCTION): 4,
    int(ViolationCategory.BUFFER_ZONE): 3,
    int(ViolationCategory.RECORD_KEEPING): 2,
    int(ViolationCategory.UNKNOWN): 2,
}


E_BAD_FARM_REF = 22001
E_BAD_DOSSIER = 22002
E_UNKNOWN_NODE = 22003
E_BAD_STATE = 22004
E_NOT_HOLDER = 22005
E_BAD_PARENT = 22006
E_BAD_KIND = 22007
E_TREE_DEPTH = 22008
E_DOSSIER_TOO_LARGE = 22009
E_BAD_LIMIT = 22010
E_NO_PARENT = 22011
E_CANNOT_BADGE_NON_CERTIFIED = 22012
E_NODE_EXISTS = 22013
E_FOREIGN_PARENT = 22014
E_BAD_ORIGIN = 22015
E_UNAUTHORIZED_ORIGIN = 22016
E_DUP_EVIDENCE = 22017
E_BAD_ANCESTOR = 22018

E_LLM_NOT_DICT = 22101
E_LLM_BAD_COUNT = 22102
E_LLM_BAD_CATEGORY = 22103
E_LLM_DISAGREE = 22104
E_LLM_BAD_SEVERITY = 22105


# --- fault wire-format (organic-cert only) ------------------------------------
# sigil + code + optional " #key=value#..." context.
#   CERT_RULE  -> deterministic node/tree/holder rule (validators match verbatim)
#   CERT_MODEL -> the LLM inspector returned unusable output
_CERT_RULE = "org=rule&"
_CERT_MODEL = "org=model&"


VIOLATION_MAX = 50
VIOLATION_VALIDATOR_TOL = 1
DOSSIER_MIN_LEN = 30
DOSSIER_MAX_LEN = 6000
FARM_REF_MAX_LEN = 96
URL_MAX_LEN = 900
EVIDENCE_BODY_MAX = 12000
EVIDENCE_SNAPSHOT_MAX = 1800
TREE_MAX_DEPTH = 3
BADGE_PREMIUM = "ORGANIC-PREMIUM"
BADGE_CONDITIONAL = "ORGANIC-CONDITIONAL"


def _facts(pairs: dict) -> str:
    if not pairs:
        return ""
    return " #" + "#".join(f"{k}={pairs[k]}" for k in sorted(pairs))


def _refuse_rule(code: int, **extra) -> None:
    raise gl.vm.UserError(f"{_CERT_RULE}{code}{_facts(extra)}")


def _refuse_model(code: int, **extra) -> None:
    raise gl.vm.UserError(f"{_CERT_MODEL}{code}{_facts(extra)}")


def _inspectors_agree_on_fault(leaders_res, rerun) -> bool:
    lead = leaders_res.message if hasattr(leaders_res, "message") else ""
    try:
        rerun()
        return False
    except gl.vm.UserError as e:
        mine = e.message if hasattr(e, "message") else str(e)
        if lead.startswith(_CERT_RULE) and mine.startswith(_CERT_RULE):
            return mine == lead
        if lead.startswith(_CERT_MODEL) and mine.startswith(_CERT_MODEL):
            return True
        if lead.startswith("org=external&") and mine.startswith("org=external&"):
            return mine == lead
        if lead.startswith("org=transient&") and mine.startswith("org=transient&"):
            return True
        return False


def _count_of(value, default=None):
    # float-free integer parse (GenVM linter forbids bare float)
    raw = str(value).strip().replace(",", "")
    neg = raw.startswith("-")
    if raw[:1] in "+-":
        raw = raw[1:]
    head = raw.split(".")[0]
    if not head.isdigit():
        return default
    return -int(head) if neg else int(head)


def _excerpt(value, n: int) -> str:
    s = value if isinstance(value, str) else str(value)
    return s[:n]


def _certhash(text: str, n: int = 24) -> str:
    try:
        return hashlib.sha256(("org=" + text).encode("utf-8", "ignore")).hexdigest()[:n]
    except Exception:
        return "0" * n


def _grower(addr) -> str:
    # checksummed hex via the SDK property
    try:
        return addr.as_hex
    except Exception:
        try:
            return "0x" + bytes(addr.as_bytes).hex()
        except Exception:
            return "0x"


def _https_origin(url: str) -> str:
    value = (url or "").strip()
    lower = value.lower()
    if not lower.startswith("https://"):
        _refuse_rule(E_BAD_ORIGIN, reason="https_required")
    rest = value[8:]
    host = rest.split("/", 1)[0].strip().lower()
    if not host or "@" in host or "#" in host or "?" in host:
        _refuse_rule(E_BAD_ORIGIN, reason="bad_host")
    return "https://" + host


def _evidence_key(url: str) -> str:
    return (url or "").strip().lower()


def _fetch_evidence(url: str) -> str:
    res = gl.nondet.web.get(url)
    status = int(getattr(res, "status", 200))
    if 400 <= status < 500:
        raise gl.vm.UserError(f"org=external&http={status}")
    if status >= 500:
        raise gl.vm.UserError(f"org=transient&http={status}")
    body = res.body.decode("utf-8", errors="ignore")[:EVIDENCE_BODY_MAX]
    if len(body.strip()) < DOSSIER_MIN_LEN:
        _refuse_rule(E_BAD_DOSSIER, reason="empty_evidence")
    return body


def _violation_category(label: str) -> ViolationCategory:
    s = (label or "").strip().upper().replace("-", "_").replace(" ", "_")
    mapping = {
        "PESTICIDE": ViolationCategory.PESTICIDE_RESIDUE,
        "PESTICIDE_RESIDUE": ViolationCategory.PESTICIDE_RESIDUE,
        "RESIDUE": ViolationCategory.PESTICIDE_RESIDUE,
        "INPUT": ViolationCategory.NON_COMPLIANT_INPUT,
        "NON_COMPLIANT_INPUT": ViolationCategory.NON_COMPLIANT_INPUT,
        "FERTILISER": ViolationCategory.NON_COMPLIANT_INPUT,
        "RECORD": ViolationCategory.RECORD_KEEPING,
        "RECORDS": ViolationCategory.RECORD_KEEPING,
        "RECORD_KEEPING": ViolationCategory.RECORD_KEEPING,
        "DOC": ViolationCategory.FORGED_DOC,
        "DOCUMENT": ViolationCategory.FORGED_DOC,
        "FORGED": ViolationCategory.FORGED_DOC,
        "FORGED_DOC": ViolationCategory.FORGED_DOC,
        "BUFFER": ViolationCategory.BUFFER_ZONE,
        "BUFFER_ZONE": ViolationCategory.BUFFER_ZONE,
        "PARALLEL": ViolationCategory.PARALLEL_PRODUCTION,
        "PARALLEL_PRODUCTION": ViolationCategory.PARALLEL_PRODUCTION,
    }
    return mapping.get(s, ViolationCategory.UNKNOWN)


def _severity(value) -> int:
    n = _count_of(value, 2)
    if n is None:
        _refuse_model(E_LLM_BAD_SEVERITY)
    if n < 1:
        return 1
    if n > 5:
        return 5
    return n


def _category_bit(category_id: int) -> int:
    return 1 << max(0, int(category_id) - 1)


def _cert_opinion(severity_total: int, count: int) -> Opinion:
    if count == 0:
        return Opinion.CERTIFIED
    if count <= 2 and severity_total <= 4:
        return Opinion.CONDITIONAL
    return Opinion.FAILED


@allow_storage
@dataclass
class Violation:
    violation_id: u32
    node_id: u32
    category: u8
    severity: u8
    note: str
    detected_seq: u64
    inherited_from_node_id: u32


@allow_storage
@dataclass
class CertNode:
    node_id: u32
    parent_id: u32
    farm_root_id: u32
    holder: Address
    kind: u8
    label: str
    farm_ref: str
    farm_ref_hash: str
    dossier: str
    dossier_hash: str
    evidence_url: str
    evidence_origin: str
    evidence_hash: str
    evidence_snapshot: str
    claimant_note: str
    state: u8
    opinion: u8
    violation_count: u32
    inherited_violation_count: u32
    severity_total: u32
    max_severity: u8
    category_mask: u32
    badge_label: str
    rationale: str
    depth: u8
    children_count: u32
    submitted_seq: u64
    inspected_seq: u64
    resolved_seq: u64
    badged_seq: u64
    revoked_seq: u64
    suspended_seq: u64


@allow_storage
@dataclass
class CertEdge:
    parent_id: u32
    child_id: u32
    depth: u8


@allow_storage
@dataclass
class CascadeLog:
    seq: u64
    triggering_node_id: u32
    affected_node_id: u32
    actor: Address
    state_from: u8
    state_to: u8
    note: str


@allow_storage
@dataclass
class HolderRoll:
    holder: Address
    nodes_count: u32
    certified_count: u32
    conditional_count: u32
    failed_count: u32
    revoked_count: u32
    badged_count: u32


class OrganicCert(gl.Contract):
    owner: Address
    nodes: TreeMap[u32, CertNode]
    children: TreeMap[u32, DynArray[u32]]
    edges: DynArray[CertEdge]
    violations: TreeMap[u32, Violation]
    node_violations: TreeMap[u32, DynArray[u32]]
    cascade_logs: DynArray[CascadeLog]
    holders: TreeMap[Address, HolderRoll]
    farm_index: TreeMap[str, u32]
    allowed_origins: TreeMap[str, bool]
    origin_list: DynArray[str]
    used_evidence: TreeMap[str, bool]
    blank_u32: DynArray[u32]
    next_node_id: u32
    next_violation_id: u32
    next_seq: u64
    submitted_count: u32
    badged_count: u32
    revoked_count: u32
    origin_count: u32

    def __init__(self):
        self.owner = gl.message.sender_address
        self.next_node_id = u32(0)
        self.next_violation_id = u32(0)
        self.next_seq = u64(1)
        self.submitted_count = u32(0)
        self.badged_count = u32(0)
        self.revoked_count = u32(0)
        self.origin_count = u32(0)

    def _alloc_seq(self) -> int:
        s = int(self.next_seq)
        self.next_seq = u64(s + 1)
        return s

    def _holder(self, addr: Address) -> HolderRoll:
        r = self.holders.get(addr)
        if r is None:
            r = HolderRoll(
                holder=addr,
                nodes_count=u32(0),
                certified_count=u32(0),
                conditional_count=u32(0),
                failed_count=u32(0),
                revoked_count=u32(0),
                badged_count=u32(0),
            )
        return r

    def _push_child(self, parent_id: int, child_id: int) -> None:
        pid = u32(int(parent_id))
        if pid not in self.children:
            self.children[pid] = self.blank_u32
        self.children[pid].append(u32(int(child_id)))

    def _log_cascade(self, triggering_node_id: int, affected_node_id: int, state_from: int, state_to: int, note: str) -> int:
        seq = self._alloc_seq()
        log = CascadeLog(
            seq=u64(seq),
            triggering_node_id=u32(int(triggering_node_id)),
            affected_node_id=u32(int(affected_node_id)),
            actor=gl.message.sender_address,
            state_from=u8(int(state_from)),
            state_to=u8(int(state_to)),
            note=_excerpt(note, 240),
        )
        self.cascade_logs.append(log)
        return seq

    def _validate_farm_ref(self, ref: str) -> str:
        s = (ref or "").strip()
        if not s:
            _refuse_rule(E_BAD_FARM_REF, reason="empty")
        if len(s) > FARM_REF_MAX_LEN:
            _refuse_rule(E_BAD_FARM_REF, reason="too_long", len=len(s))
        return s

    def _validate_dossier(self, dossier: str) -> str:
        s = dossier or ""
        if len(s.strip()) < DOSSIER_MIN_LEN:
            _refuse_rule(E_BAD_DOSSIER, reason="too_short", min=DOSSIER_MIN_LEN)
        if len(s) > DOSSIER_MAX_LEN:
            _refuse_rule(E_DOSSIER_TOO_LARGE, max=DOSSIER_MAX_LEN)
        return s

    def _require_node(self, node_id: u32) -> CertNode:
        if node_id not in self.nodes:
            _refuse_rule(E_UNKNOWN_NODE, node_id=int(node_id))
        return self.nodes[node_id]

    def _require_holder(self, node: CertNode) -> None:
        if node.holder != gl.message.sender_address:
            _refuse_rule(E_NOT_HOLDER, expected=_grower(node.holder), actor=_grower(gl.message.sender_address))

    def _require_owner(self) -> None:
        if gl.message.sender_address != self.owner:
            _refuse_rule(E_NOT_HOLDER, expected=_grower(self.owner), actor=_grower(gl.message.sender_address))

    def _validate_evidence_url(self, url: str, consume: bool) -> tuple[str, str]:
        value = (url or "").strip()
        if len(value) > URL_MAX_LEN:
            _refuse_rule(E_BAD_ORIGIN, reason="url_too_long")
        origin = _https_origin(value)
        allowed = self.allowed_origins.get(origin)
        if not bool(allowed):
            _refuse_rule(E_UNAUTHORIZED_ORIGIN, origin=origin)
        key = _evidence_key(value)
        if consume and bool(self.used_evidence.get(key)):
            _refuse_rule(E_DUP_EVIDENCE, hash=_certhash(key, 16))
        if consume:
            self.used_evidence[key] = True
        return value, origin

    def _ancestor_chain_eligible(self, node: CertNode, require_badged: bool) -> bool:
        if int(node.parent_id) == int(node.node_id):
            return True
        current = int(node.parent_id)
        guard = 0
        while guard < TREE_MAX_DEPTH + 2:
            parent = self.nodes.get(u32(current))
            if parent is None:
                return False
            if int(parent.state) in (int(CertState.SUSPENDED), int(CertState.REVOKED), int(CertState.CASCADED)):
                return False
            if int(parent.opinion) == int(Opinion.FAILED):
                return False
            if require_badged and int(parent.state) != int(CertState.BADGED):
                return False
            if int(parent.parent_id) == int(parent.node_id):
                return True
            current = int(parent.parent_id)
            guard += 1
        return False

    def _require_ancestor_chain_eligible(self, node: CertNode, require_badged: bool) -> None:
        if not self._ancestor_chain_eligible(node, require_badged):
            _refuse_rule(E_BAD_ANCESTOR, node_id=int(node.node_id))

    @gl.public.write
    def authorize_evidence_origin(self, origin: str, authorized: bool) -> None:
        self._require_owner()
        clean = _https_origin(origin)
        current = bool(self.allowed_origins.get(clean))
        self.allowed_origins[clean] = authorized
        if authorized and not current:
            self.origin_list.append(clean)
            self.origin_count = u32(int(self.origin_count) + 1)

    @gl.public.write
    def submit_farm(self, farm_ref: str, label: str, evidence_url: str, claimant_note: str) -> u32:
        ref = self._validate_farm_ref(farm_ref)
        ref_hash = _certhash(ref.lower(), 24)
        if ref_hash in self.farm_index:
            existing = int(self.farm_index[ref_hash])
            _refuse_rule(E_NODE_EXISTS, farm_ref=ref, existing_node_id=existing)
        url, origin = self._validate_evidence_url(evidence_url, True)
        note = _excerpt(claimant_note, DOSSIER_MAX_LEN)
        nid = int(self.next_node_id)
        seq = self._alloc_seq()
        node = CertNode(
            node_id=u32(nid),
            parent_id=u32(nid),
            farm_root_id=u32(nid),
            holder=gl.message.sender_address,
            kind=u8(int(NodeKind.FARM)),
            label=_excerpt(label, 96),
            farm_ref=ref,
            farm_ref_hash=ref_hash,
            dossier=note,
            dossier_hash=_certhash(note, 32),
            evidence_url=url,
            evidence_origin=origin,
            evidence_hash=_certhash(url, 32),
            evidence_snapshot="",
            claimant_note=note,
            state=u8(int(CertState.SUBMITTED)),
            opinion=u8(int(Opinion.PENDING)),
            violation_count=u32(0),
            inherited_violation_count=u32(0),
            severity_total=u32(0),
            max_severity=u8(0),
            category_mask=u32(0),
            badge_label="",
            rationale="",
            depth=u8(0),
            children_count=u32(0),
            submitted_seq=u64(seq),
            inspected_seq=u64(0),
            resolved_seq=u64(0),
            badged_seq=u64(0),
            revoked_seq=u64(0),
            suspended_seq=u64(0),
        )
        self.nodes[u32(nid)] = node
        self.farm_index[ref_hash] = u32(nid)
        roll = self._holder(gl.message.sender_address)
        roll.nodes_count = u32(int(roll.nodes_count) + 1)
        self.holders[gl.message.sender_address] = roll
        self.submitted_count = u32(int(self.submitted_count) + 1)
        self.next_node_id = u32(nid + 1)
        return u32(nid)

    @gl.public.write
    def add_child(self, parent_id: u32, kind: u8, label: str, evidence_url: str, claimant_note: str) -> u32:
        parent = self._require_node(parent_id)
        self._require_holder(parent)
        if int(parent.state) != int(CertState.BADGED):
            _refuse_rule(E_BAD_ANCESTOR, parent_id=int(parent.node_id), state=CERT_STATE_NAMES[int(parent.state)])
        if int(parent.opinion) == int(Opinion.FAILED):
            _refuse_rule(E_BAD_ANCESTOR, parent_id=int(parent.node_id), opinion=OPINION_NAMES[int(parent.opinion)])
        try:
            child_kind = NodeKind(int(kind))
        except ValueError:
            _refuse_rule(E_BAD_KIND, kind=int(kind))
        if child_kind == NodeKind.FARM:
            _refuse_rule(E_BAD_KIND, reason="farm_must_use_submit_farm")
        if child_kind == NodeKind.PLOT and int(parent.kind) != int(NodeKind.FARM):
            _refuse_rule(E_BAD_PARENT, parent_kind=NODE_KIND_NAMES[int(parent.kind)], expected="FARM")
        if child_kind == NodeKind.BATCH and int(parent.kind) != int(NodeKind.PLOT):
            _refuse_rule(E_BAD_PARENT, parent_kind=NODE_KIND_NAMES[int(parent.kind)], expected="PLOT")
        if int(parent.depth) >= TREE_MAX_DEPTH - 1:
            _refuse_rule(E_TREE_DEPTH, depth=int(parent.depth), max=TREE_MAX_DEPTH)
        if int(parent.state) == int(CertState.REVOKED) or int(parent.state) == int(CertState.SUSPENDED):
            _refuse_rule(E_BAD_STATE, parent_state=CERT_STATE_NAMES[int(parent.state)])
        url, origin = self._validate_evidence_url(evidence_url, True)
        if origin != parent.evidence_origin:
            _refuse_rule(E_FOREIGN_PARENT, parent_origin=parent.evidence_origin, child_origin=origin)
        note = _excerpt(claimant_note, DOSSIER_MAX_LEN)
        nid = int(self.next_node_id)
        seq = self._alloc_seq()
        node = CertNode(
            node_id=u32(nid),
            parent_id=parent.node_id,
            farm_root_id=parent.farm_root_id,
            holder=gl.message.sender_address,
            kind=u8(int(child_kind)),
            label=_excerpt(label, 96),
            farm_ref=parent.farm_ref,
            farm_ref_hash=parent.farm_ref_hash,
            dossier=note,
            dossier_hash=_certhash(note, 32),
            evidence_url=url,
            evidence_origin=origin,
            evidence_hash=_certhash(url, 32),
            evidence_snapshot="",
            claimant_note=note,
            state=u8(int(CertState.SUBMITTED)),
            opinion=u8(int(Opinion.PENDING)),
            violation_count=u32(0),
            inherited_violation_count=u32(0),
            severity_total=u32(0),
            max_severity=u8(0),
            category_mask=u32(0),
            badge_label="",
            rationale="",
            depth=u8(int(parent.depth) + 1),
            children_count=u32(0),
            submitted_seq=u64(seq),
            inspected_seq=u64(0),
            resolved_seq=u64(0),
            badged_seq=u64(0),
            revoked_seq=u64(0),
            suspended_seq=u64(0),
        )
        self.nodes[u32(nid)] = node
        self._push_child(int(parent.node_id), nid)
        edge = CertEdge(parent_id=parent.node_id, child_id=u32(nid), depth=u8(int(node.depth)))
        self.edges.append(edge)
        parent.children_count = u32(int(parent.children_count) + 1)
        self.nodes[parent.node_id] = parent
        roll = self._holder(gl.message.sender_address)
        roll.nodes_count = u32(int(roll.nodes_count) + 1)
        self.holders[gl.message.sender_address] = roll
        self.submitted_count = u32(int(self.submitted_count) + 1)
        self.next_node_id = u32(nid + 1)
        return u32(nid)

    @gl.public.write
    def run_inspection(self, node_id: u32) -> u64:
        node = self._require_node(node_id)
        if int(node.state) != int(CertState.SUBMITTED):
            _refuse_rule(E_BAD_STATE, state=CERT_STATE_NAMES[int(node.state)])
        self._require_ancestor_chain_eligible(node, True)
        snap = gl.storage.copy_to_memory(node)
        claimant_note = snap.claimant_note[:DOSSIER_MAX_LEN]
        evidence_url = snap.evidence_url
        farm_ref = snap.farm_ref
        kind = NODE_KIND_NAMES[int(snap.kind)]
        label = snap.label

        def call_inspect():
            evidence_text = _fetch_evidence(evidence_url)
            prompt = (
                "You are an organic supply-chain inspector. Use the CERTIFIER_OR_LAB_EVIDENCE as the authority. "
                "The CLAIMANT_NOTE is context only and cannot prove compliance or non-compliance by itself. "
                "Decide distinct organic-standard violation categories and a 1-5 severity for each category. "
                "Controlled categories: PESTICIDE_RESIDUE, NON_COMPLIANT_INPUT, RECORD_KEEPING, FORGED_DOC, "
                "BUFFER_ZONE, PARALLEL_PRODUCTION, UNKNOWN. Return only facts supported by the fetched evidence.\n"
                f"Farm ref: {farm_ref}\n"
                f"Node kind: {kind} | Label: {label}\n"
                f"Evidence URL: {evidence_url}\n"
                f"---CLAIMANT_NOTE---\n{claimant_note}\n---CLAIMANT_NOTE---\n"
                f"---CERTIFIER_OR_LAB_EVIDENCE---\n{evidence_text}\n---CERTIFIER_OR_LAB_EVIDENCE---\n"
                'Return strict JSON: {"violations":[{"category":"<CAT>","severity":<1-5 int>,"note":"<=120"}],"standard_violations":<0-50 int>,"rationale":"<=480 chars citing fetched evidence"}'
            )
            raw = gl.nondet.exec_prompt(prompt, response_format="json")
            if not isinstance(raw, dict):
                _refuse_model(E_LLM_NOT_DICT, step="inspect")
            count = _count_of(raw.get("standard_violations"), -1)
            if count is None or count < 0 or count > VIOLATION_MAX:
                _refuse_model(E_LLM_BAD_COUNT, got=count)
            violations_raw = raw.get("violations")
            if not isinstance(violations_raw, list):
                _refuse_model(E_LLM_NOT_DICT, step="violations_list")
            cleaned = []
            severity_total = 0
            max_severity = 0
            category_mask = 0
            for v in violations_raw[:VIOLATION_MAX]:
                if not isinstance(v, dict):
                    continue
                cat = _violation_category(v.get("category", ""))
                severity = _severity(v.get("severity", VIOLATION_SEVERITY.get(int(cat), 2)))
                severity_total += severity
                if severity > max_severity:
                    max_severity = severity
                category_mask = category_mask | _category_bit(int(cat))
                cleaned.append({
                    "category": int(cat),
                    "severity": int(severity),
                    "note": _excerpt(v.get("note", ""), 120),
                })
            if len(cleaned) > count:
                cleaned = cleaned[:count]
                severity_total = 0
                max_severity = 0
                category_mask = 0
                for v in cleaned:
                    sev = int(v.get("severity", 2))
                    severity_total += sev
                    if sev > max_severity:
                        max_severity = sev
                    category_mask = category_mask | _category_bit(int(v.get("category", int(ViolationCategory.UNKNOWN))))
            opinion = _cert_opinion(severity_total, count)
            return {
                "violations": cleaned,
                "standard_violations": int(count),
                "severity_total": int(severity_total),
                "max_severity": int(max_severity),
                "category_mask": int(category_mask),
                "opinion": int(opinion),
                "rationale": _excerpt(raw.get("rationale", ""), 480),
                "evidence_snapshot": _excerpt(evidence_text, EVIDENCE_SNAPSHOT_MAX),
            }

        def validate_inspect(leaders_res):
            if not isinstance(leaders_res, gl.vm.Return):
                return _inspectors_agree_on_fault(leaders_res, call_inspect)
            data = leaders_res.calldata
            if not isinstance(data, dict):
                return False
            leader_count = _count_of(data.get("standard_violations"), -1)
            if leader_count is None or leader_count < 0 or leader_count > VIOLATION_MAX:
                return False
            try:
                mine = call_inspect()
            except gl.vm.UserError:
                return False
            my_count = int(mine.get("standard_violations", 0))
            if abs(my_count - int(leader_count)) > VIOLATION_VALIDATOR_TOL:
                return False
            leader_opinion = _count_of(data.get("opinion"), -1)
            if int(mine.get("opinion", -2)) != int(leader_opinion):
                return False
            leader_mask = _count_of(data.get("category_mask"), -1)
            my_mask = int(mine.get("category_mask", 0))
            if int(leader_count) == 0 and my_count == 0:
                return True
            if int(leader_mask) != my_mask:
                return False
            leader_max = _count_of(data.get("max_severity"), -1)
            if int(mine.get("max_severity", -2)) != int(leader_max):
                return False
            return True

        outcome = gl.vm.run_nondet_unsafe(call_inspect, validate_inspect)
        violations_data = outcome.get("violations", [])
        count = int(outcome.get("standard_violations", 0))
        rationale = _excerpt(outcome.get("rationale", ""), 480)
        severity_total = 0
        max_severity = 0
        category_mask = 0
        seq = self._alloc_seq()
        node = self._require_node(node_id)
        for v in violations_data:
            vid = int(self.next_violation_id)
            severity = int(v.get("severity", 2))
            severity_total += severity
            if severity > max_severity:
                max_severity = severity
            category_id = int(v.get("category", int(ViolationCategory.UNKNOWN)))
            category_mask = category_mask | _category_bit(category_id)
            violation = Violation(
                violation_id=u32(vid),
                node_id=node.node_id,
                category=u8(category_id),
                severity=u8(severity),
                note=str(v.get("note", "")),
                detected_seq=u64(seq),
                inherited_from_node_id=u32(0),
            )
            self.violations[u32(vid)] = violation
            if node.node_id not in self.node_violations:
                self.node_violations[node.node_id] = self.blank_u32
            self.node_violations[node.node_id].append(u32(vid))
            self.next_violation_id = u32(vid + 1)
        opinion = _cert_opinion(severity_total, count)
        node.violation_count = u32(count)
        node.severity_total = u32(severity_total)
        node.max_severity = u8(max_severity)
        node.category_mask = u32(category_mask)
        node.opinion = u8(int(opinion))
        node.rationale = rationale
        node.evidence_snapshot = _excerpt(outcome.get("evidence_snapshot", ""), EVIDENCE_SNAPSHOT_MAX)
        node.state = u8(int(CertState.RESOLVED))
        node.inspected_seq = u64(seq)
        node.resolved_seq = u64(seq)
        self.nodes[node_id] = node
        roll = self._holder(node.holder)
        if opinion == Opinion.CERTIFIED:
            roll.certified_count = u32(int(roll.certified_count) + 1)
        elif opinion == Opinion.CONDITIONAL:
            roll.conditional_count = u32(int(roll.conditional_count) + 1)
        else:
            roll.failed_count = u32(int(roll.failed_count) + 1)
        self.holders[node.holder] = roll
        return u64(seq)

    @gl.public.write
    def issue_badge(self, node_id: u32) -> str:
        node = self._require_node(node_id)
        if int(node.state) != int(CertState.RESOLVED):
            _refuse_rule(E_BAD_STATE, state=CERT_STATE_NAMES[int(node.state)])
        self._require_ancestor_chain_eligible(node, True)
        op = Opinion(int(node.opinion))
        if op == Opinion.FAILED:
            _refuse_rule(E_CANNOT_BADGE_NON_CERTIFIED, opinion=OPINION_NAMES[int(op)])
        badge = BADGE_PREMIUM if op == Opinion.CERTIFIED else BADGE_CONDITIONAL
        seq = self._alloc_seq()
        node.state = u8(int(CertState.BADGED))
        node.badge_label = (
            f"{badge}#node{int(node_id)}@{node.farm_ref_hash[:16]}"
            f"|kind={NODE_KIND_NAMES[int(node.kind)]}"
            f"|violations={int(node.violation_count)}/{VIOLATION_MAX}"
        )
        node.badged_seq = u64(seq)
        self.nodes[node_id] = node
        roll = self._holder(node.holder)
        roll.badged_count = u32(int(roll.badged_count) + 1)
        self.holders[node.holder] = roll
        self.badged_count = u32(int(self.badged_count) + 1)
        return node.badge_label

    def _cascade_revoke(self, root_node_id: int, reason: str) -> int:
        affected = 0
        stack = [int(root_node_id)]
        while stack:
            current = stack.pop()
            node = self.nodes.get(u32(current))
            if node is None:
                continue
            if int(node.state) == int(CertState.REVOKED) or int(node.state) == int(CertState.CASCADED):
                continue
            previous_state = int(node.state)
            new_state = int(CertState.CASCADED) if current != int(root_node_id) else int(CertState.REVOKED)
            node.state = u8(new_state)
            seq_no = self._alloc_seq()
            if new_state == int(CertState.REVOKED):
                node.revoked_seq = u64(seq_no)
            node.opinion = u8(int(Opinion.FAILED))
            node.badge_label = ""
            self.nodes[u32(current)] = node
            roll = self._holder(node.holder)
            roll.revoked_count = u32(int(roll.revoked_count) + 1)
            self.holders[node.holder] = roll
            self._log_cascade(int(root_node_id), current, previous_state, new_state, _excerpt(reason, 240) or "cascade")
            children = self.children.get(u32(current))
            if children is not None:
                m = len(children)
                j = 0
                while j < m:
                    stack.append(int(children[j]))
                    j += 1
            affected += 1
        return affected

    def _cascade_suspend(self, root_node_id: int, reason: str) -> int:
        affected = 0
        stack = [int(root_node_id)]
        while stack:
            current = stack.pop()
            node = self.nodes.get(u32(current))
            if node is None:
                continue
            if int(node.state) in (int(CertState.REVOKED), int(CertState.SUSPENDED), int(CertState.CASCADED)):
                continue
            previous_state = int(node.state)
            new_state = int(CertState.CASCADED) if current != int(root_node_id) else int(CertState.SUSPENDED)
            node.state = u8(new_state)
            node.badge_label = ""
            seq_no = self._alloc_seq()
            node.suspended_seq = u64(seq_no)
            self.nodes[u32(current)] = node
            self._log_cascade(int(root_node_id), current, previous_state, new_state, _excerpt(reason, 240) or "suspended")
            children = self.children.get(u32(current))
            if children is not None:
                m = len(children)
                j = 0
                while j < m:
                    stack.append(int(children[j]))
                    j += 1
            affected += 1
        return affected

    def _reinstate_subtree(self, root_node_id: int) -> int:
        affected = 0
        stack = [int(root_node_id)]
        while stack:
            current = stack.pop()
            node = self.nodes.get(u32(current))
            if node is None:
                continue
            if int(node.state) in (int(CertState.SUSPENDED), int(CertState.CASCADED)):
                if not self._ancestor_chain_eligible(node, False):
                    _refuse_rule(E_BAD_ANCESTOR, node_id=current)
                previous_state = int(node.state)
                new_state = int(CertState.RESOLVED) if int(node.opinion) != int(Opinion.PENDING) else int(CertState.SUBMITTED)
                if int(node.opinion) == int(Opinion.FAILED):
                    new_state = int(CertState.RESOLVED)
                node.state = u8(new_state)
                self.nodes[u32(current)] = node
                self._log_cascade(int(root_node_id), current, previous_state, new_state, "reinstated")
                affected += 1
            children = self.children.get(u32(current))
            if children is not None:
                m = len(children)
                j = 0
                while j < m:
                    stack.append(int(children[j]))
                    j += 1
        return affected

    @gl.public.write
    def revoke_node(self, node_id: u32, reason: str) -> dict:
        node = self._require_node(node_id)
        self._require_holder(node)
        if int(node.state) == int(CertState.REVOKED):
            _refuse_rule(E_BAD_STATE, state=CERT_STATE_NAMES[int(node.state)])
        affected = self._cascade_revoke(int(node_id), reason)
        self.revoked_count = u32(int(self.revoked_count) + 1)
        return {
            "node_id": int(node_id),
            "affected_nodes": affected,
        }

    @gl.public.write
    def suspend_node(self, node_id: u32, reason: str) -> u64:
        node = self._require_node(node_id)
        self._require_holder(node)
        if int(node.state) in (int(CertState.REVOKED), int(CertState.CASCADED), int(CertState.SUSPENDED)):
            _refuse_rule(E_BAD_STATE, state=CERT_STATE_NAMES[int(node.state)])
        affected = self._cascade_suspend(int(node_id), reason)
        return u64(affected)

    @gl.public.write
    def reinstate_node(self, node_id: u32) -> u64:
        node = self._require_node(node_id)
        self._require_holder(node)
        if int(node.state) not in (int(CertState.SUSPENDED), int(CertState.CASCADED)):
            _refuse_rule(E_BAD_STATE, state=CERT_STATE_NAMES[int(node.state)])
        affected = self._reinstate_subtree(int(node_id))
        return u64(affected)

    @gl.public.view
    def get_node(self, node_id: u32) -> CertNode:
        return self._require_node(node_id)

    @gl.public.view
    def get_node_card(self, node_id: u32) -> dict:
        node = self._require_node(node_id)
        return {
            "node_id": int(node.node_id),
            "parent_id": int(node.parent_id),
            "farm_root_id": int(node.farm_root_id),
            "holder": _grower(node.holder),
            "kind": NODE_KIND_NAMES[int(node.kind)],
            "label": node.label,
            "farm_ref": node.farm_ref,
            "farm_ref_hash": node.farm_ref_hash,
            "dossier_hash": node.dossier_hash,
            "evidence_url": node.evidence_url,
            "evidence_origin": node.evidence_origin,
            "evidence_hash": node.evidence_hash,
            "evidence_snapshot": node.evidence_snapshot,
            "state": CERT_STATE_NAMES[int(node.state)],
            "opinion": OPINION_NAMES[int(node.opinion)],
            "violation_count": int(node.violation_count),
            "inherited_violation_count": int(node.inherited_violation_count),
            "severity_total": int(node.severity_total),
            "max_severity": int(node.max_severity),
            "category_mask": int(node.category_mask),
            "badge_label": node.badge_label,
            "depth": int(node.depth),
            "children_count": int(node.children_count),
            "rationale": node.rationale,
            "submitted_seq": int(node.submitted_seq),
            "inspected_seq": int(node.inspected_seq),
            "resolved_seq": int(node.resolved_seq),
            "badged_seq": int(node.badged_seq),
            "revoked_seq": int(node.revoked_seq),
            "suspended_seq": int(node.suspended_seq),
        }

    @gl.public.view
    def get_node_violations(self, node_id: u32) -> list:
        bucket = self.node_violations.get(node_id)
        if bucket is None:
            return []
        out = []
        n = len(bucket)
        i = 0
        while i < n:
            vid = bucket[i]
            v = self.violations.get(vid)
            if v is not None:
                out.append({
                    "violation_id": int(v.violation_id),
                    "node_id": int(v.node_id),
                    "category": VIOLATION_CATEGORY_NAMES[int(v.category)],
                    "severity": int(v.severity),
                    "note": v.note,
                    "detected_seq": int(v.detected_seq),
                    "inherited_from_node_id": int(v.inherited_from_node_id),
                })
            i += 1
        return out

    @gl.public.view
    def get_children(self, parent_id: u32) -> list:
        bucket = self.children.get(parent_id)
        if bucket is None:
            return []
        out = []
        n = len(bucket)
        i = 0
        while i < n:
            cid = bucket[i]
            node = self.nodes.get(cid)
            if node is not None:
                out.append({
                    "node_id": int(cid),
                    "kind": NODE_KIND_NAMES[int(node.kind)],
                    "label": node.label,
                    "state": CERT_STATE_NAMES[int(node.state)],
                    "opinion": OPINION_NAMES[int(node.opinion)],
                    "violation_count": int(node.violation_count),
                    "max_severity": int(node.max_severity),
                    "badge_label": node.badge_label,
                })
            i += 1
        return out

    @gl.public.view
    def get_subtree(self, root_id: u32) -> list:
        out = []
        stack = [int(root_id)]
        seen = {}
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen[current] = True
            node = self.nodes.get(u32(current))
            if node is None:
                continue
            out.append({
                "node_id": int(node.node_id),
                "parent_id": int(node.parent_id),
                "kind": NODE_KIND_NAMES[int(node.kind)],
                "label": node.label,
                "state": CERT_STATE_NAMES[int(node.state)],
                "opinion": OPINION_NAMES[int(node.opinion)],
                "depth": int(node.depth),
                "violation_count": int(node.violation_count),
                "max_severity": int(node.max_severity),
                "children_count": int(node.children_count),
            })
            children = self.children.get(node.node_id)
            if children is not None:
                m = len(children)
                j = 0
                while j < m:
                    stack.append(int(children[j]))
                    j += 1
        return out

    @gl.public.view
    def resolve_farm_node(self, farm_ref: str) -> dict:
        ref = self._validate_farm_ref(farm_ref)
        h = _certhash(ref.lower(), 24)
        nid = self.farm_index.get(h)
        if nid is None:
            return {"farm_ref": ref, "exists": False}
        node = self.nodes.get(nid)
        if node is None:
            return {"farm_ref": ref, "exists": False}
        return {
            "farm_ref": ref,
            "exists": True,
            "node_id": int(nid),
            "state": CERT_STATE_NAMES[int(node.state)],
            "opinion": OPINION_NAMES[int(node.opinion)],
            "children_count": int(node.children_count),
            "badge_label": node.badge_label,
        }

    @gl.public.view
    def get_cascade_logs(self, offset: u32, limit: u32) -> list:
        off = int(offset)
        lim = int(limit)
        if off < 0 or lim <= 0 or lim > 500:
            _refuse_rule(E_BAD_LIMIT, offset=off, limit=lim)
        out = []
        n = len(self.cascade_logs)
        seen = 0
        emitted = 0
        i = 0
        while i < n and emitted < lim:
            if seen >= off:
                log = self.cascade_logs[i]
                out.append({
                    "seq": int(log.seq),
                    "triggering_node_id": int(log.triggering_node_id),
                    "affected_node_id": int(log.affected_node_id),
                    "actor": _grower(log.actor),
                    "state_from": CERT_STATE_NAMES.get(int(log.state_from), str(int(log.state_from))),
                    "state_to": CERT_STATE_NAMES.get(int(log.state_to), str(int(log.state_to))),
                    "note": log.note,
                })
                emitted += 1
            seen += 1
            i += 1
        return out

    @gl.public.view
    def get_holder_roll(self, holder: Address) -> dict:
        r = self.holders.get(holder)
        if r is None:
            return {"holder": _grower(holder), "exists": False}
        return {
            "holder": _grower(r.holder),
            "exists": True,
            "nodes_count": int(r.nodes_count),
            "certified_count": int(r.certified_count),
            "conditional_count": int(r.conditional_count),
            "failed_count": int(r.failed_count),
            "revoked_count": int(r.revoked_count),
            "badged_count": int(r.badged_count),
        }

    @gl.public.view
    def cert_stats(self) -> dict:
        return {
            "next_node_id": int(self.next_node_id),
            "next_violation_id": int(self.next_violation_id),
            "next_seq": int(self.next_seq),
            "submitted_count": int(self.submitted_count),
            "badged_count": int(self.badged_count),
            "revoked_count": int(self.revoked_count),
            "origin_count": int(self.origin_count),
        }

    @gl.public.view
    def get_evidence_origins(self) -> list:
        out = []
        n = len(self.origin_list)
        i = 0
        while i < n:
            origin = self.origin_list[i]
            out.append({
                "origin": origin,
                "authorized": bool(self.allowed_origins.get(origin)),
            })
            i += 1
        return out

    @gl.public.view
    def get_state_distribution(self) -> dict:
        counts = {CERT_STATE_NAMES[int(s)]: 0 for s in CertState}
        for nid in self.nodes:
            node = self.nodes[nid]
            counts[CERT_STATE_NAMES[int(node.state)]] += 1
        return counts

    @gl.public.view
    def get_opinion_distribution(self) -> dict:
        counts = {OPINION_NAMES[int(o)]: 0 for o in Opinion}
        for nid in self.nodes:
            node = self.nodes[nid]
            counts[OPINION_NAMES[int(node.opinion)]] += 1
        return counts

    @gl.public.view
    def get_kind_distribution(self) -> dict:
        counts = {NODE_KIND_NAMES[int(k)]: 0 for k in NodeKind}
        for nid in self.nodes:
            node = self.nodes[nid]
            counts[NODE_KIND_NAMES[int(node.kind)]] += 1
        return counts

    @gl.public.view
    def get_violation_distribution(self) -> dict:
        counts = {VIOLATION_CATEGORY_NAMES[int(c)]: 0 for c in ViolationCategory}
        for vid in self.violations:
            v = self.violations[vid]
            counts[VIOLATION_CATEGORY_NAMES[int(v.category)]] += 1
        return counts

    @gl.public.view
    def list_violation_categories(self) -> list:
        return [
            {
                "category_id": int(c),
                "name": VIOLATION_CATEGORY_NAMES[int(c)],
                "severity": VIOLATION_SEVERITY[int(c)],
            }
            for c in ViolationCategory
        ]

    @gl.public.view
    def list_node_kinds(self) -> list:
        return [
            {"kind_id": int(k), "name": NODE_KIND_NAMES[int(k)]}
            for k in NodeKind
        ]

    @gl.public.view
    def list_cert_states(self) -> list:
        return [CERT_STATE_NAMES[int(s)] for s in CertState]

    @gl.public.view
    def get_ancestors(self, node_id: u32) -> list:
        node = self._require_node(node_id)
        out = []
        if int(node.parent_id) == int(node.node_id):
            return out
        current = int(node.parent_id)
        guard = 0
        while guard < TREE_MAX_DEPTH + 2:
            parent = self.nodes.get(u32(current))
            if parent is None:
                break
            out.append({
                "node_id": int(parent.node_id),
                "kind": NODE_KIND_NAMES[int(parent.kind)],
                "label": parent.label,
                "state": CERT_STATE_NAMES[int(parent.state)],
            })
            if int(parent.parent_id) == int(parent.node_id):
                break
            current = int(parent.parent_id)
            guard += 1
        return out

    @gl.public.view
    def get_edges_under(self, parent_id: u32) -> list:
        out = []
        n = len(self.edges)
        i = 0
        while i < n:
            e = self.edges[i]
            if int(e.parent_id) == int(parent_id):
                out.append({
                    "parent_id": int(e.parent_id),
                    "child_id": int(e.child_id),
                    "depth": int(e.depth),
                })
            i += 1
        return out

    @gl.public.view
    def get_node_badge(self, node_id: u32) -> str:
        node = self._require_node(node_id)
        return node.badge_label or ""
