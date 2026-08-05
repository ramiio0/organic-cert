import json


CONTRACT = "backend/organic-cert.py"
ORIGIN = "https://cert.example.org"


def llm_prompt_for(url):
    return "[\\s\\S]*CERTIFIER_OR_LAB_EVIDENCE[\\s\\S]*Evidence URL: " + url.replace(".", r"\.") + "[\\s\\S]*"


def deploy(direct_vm, direct_deploy, owner):
    direct_vm.sender = owner
    contract = direct_deploy(CONTRACT)
    contract.authorize_evidence_origin(ORIGIN, True)
    return contract


def mock_clean(direct_vm, url):
    direct_vm.mock_web(
        url.replace(".", r"\."),
        {
            "status": 200,
            "body": (
                "Certified organic registry record. Lab residue screen clear. "
                "No prohibited pesticides detected. Input records complete. "
                "Buffer-zone documentation verified by the certifier."
            ),
        },
    )
    direct_vm.mock_llm(
        llm_prompt_for(url),
        json.dumps(
            {
                "violations": [],
                "standard_violations": 0,
                "rationale": "Fetched certifier record and lab screen show clear organic compliance.",
            }
        ),
    )


def mock_record_gap(direct_vm, url):
    direct_vm.mock_web(
        url.replace(".", r"\."),
        {
            "status": 200,
            "body": (
                "Certifier audit record. Organic status remains active, but harvest logs "
                "for one lot are incomplete and must be repaired before the next audit."
            ),
        },
    )
    direct_vm.mock_llm(
        llm_prompt_for(url),
        json.dumps(
            {
                "violations": [
                    {
                        "category": "RECORD_KEEPING",
                        "severity": 2,
                        "note": "Harvest records incomplete for one lot.",
                    }
                ],
                "standard_violations": 1,
                "rationale": "Fetched audit record reports an incomplete harvest-log issue.",
            }
        ),
    )


def test_origin_authorization_unique_evidence_and_core_views(direct_vm, direct_deploy, direct_owner, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_owner)

    with direct_vm.prank(direct_bob):
        with direct_vm.expect_revert("22005"):
            contract.authorize_evidence_origin("https://evil.example", True)

    with direct_vm.prank(direct_alice):
        with direct_vm.expect_revert("22016"):
            contract.submit_farm(
                "Farm Unauthorized",
                "Leafy greens",
                "https://unknown.example/farms/1",
                "claimant note cannot certify this farm",
            )

    with direct_vm.prank(direct_alice):
        node_id = contract.submit_farm(
            "Farm A",
            "Leafy greens",
            f"{ORIGIN}/farms/a",
            "grower submitted context only",
        )
        assert int(node_id) == 0
        with direct_vm.expect_revert("22017"):
            contract.submit_farm(
                "Farm B",
                "Stone fruit",
                f"{ORIGIN}/farms/a",
                "duplicate evidence URL",
            )

    card = contract.get_node_card(0)
    assert card["evidence_origin"] == ORIGIN
    assert card["state"] == "SUBMITTED"
    assert card["opinion"] == "PENDING"
    assert contract.resolve_farm_node("Farm A")["node_id"] == 0
    assert contract.cert_stats()["origin_count"] == 1
    assert contract.get_evidence_origins()[0]["authorized"] is True


def test_fetched_evidence_drives_categories_severity_and_badge(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_owner)
    url = f"{ORIGIN}/farms/clean"
    mock_clean(direct_vm, url)

    with direct_vm.prank(direct_alice):
        contract.submit_farm("Clean Farm", "Tomatoes", url, "claimant says everything is clean")
        contract.run_inspection(0)
        badge = contract.issue_badge(0)

    card = contract.get_node_card(0)
    assert card["opinion"] == "CERTIFIED"
    assert card["state"] == "BADGED"
    assert card["violation_count"] == 0
    assert card["max_severity"] == 0
    assert card["category_mask"] == 0
    assert "ORGANIC-PREMIUM" in badge
    assert "Certified organic registry record" in card["evidence_snapshot"]

    dist = contract.get_opinion_distribution()
    assert dist["CERTIFIED"] == 1
    assert contract.get_node_badge(0) == badge


def test_parent_must_be_badged_before_child_and_tree_views(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_owner)
    farm_url = f"{ORIGIN}/farms/tree-root"
    plot_url = f"{ORIGIN}/plots/tree-plot"
    mock_clean(direct_vm, farm_url)

    with direct_vm.prank(direct_alice):
        contract.submit_farm("Tree Farm", "Grapes", farm_url, "root note")
        with direct_vm.expect_revert("22018"):
            contract.add_child(0, 2, "North plot", plot_url, "plot note")
        contract.run_inspection(0)
        contract.issue_badge(0)

    mock_record_gap(direct_vm, plot_url)
    with direct_vm.prank(direct_alice):
        child_id = contract.add_child(0, 2, "North plot", plot_url, "plot context")
        assert int(child_id) == 1
        contract.run_inspection(1)
        contract.issue_badge(1)

    child = contract.get_node_card(1)
    assert child["opinion"] == "CONDITIONAL"
    assert child["violation_count"] == 1
    assert child["max_severity"] == 2
    assert child["category_mask"] > 0
    assert contract.get_children(0)[0]["node_id"] == 1
    assert contract.get_ancestors(1)[0]["node_id"] == 0
    subtree = contract.get_subtree(0)
    assert {row["node_id"] for row in subtree} == {0, 1}


def test_suspension_reinstatement_and_revocation_cascade(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy(direct_vm, direct_deploy, direct_owner)
    farm_url = f"{ORIGIN}/farms/cascade-root"
    plot_url = f"{ORIGIN}/plots/cascade-plot"
    batch_url = f"{ORIGIN}/batches/cascade-batch"

    mock_clean(direct_vm, farm_url)
    with direct_vm.prank(direct_alice):
        contract.submit_farm("Cascade Farm", "Tree nuts", farm_url, "root note")
        contract.run_inspection(0)
        contract.issue_badge(0)

    mock_clean(direct_vm, plot_url)
    with direct_vm.prank(direct_alice):
        contract.add_child(0, 2, "Orchard block", plot_url, "plot note")
        contract.run_inspection(1)
        contract.issue_badge(1)

    mock_clean(direct_vm, batch_url)
    with direct_vm.prank(direct_alice):
        contract.add_child(1, 3, "Batch 24-A", batch_url, "batch note")
        contract.run_inspection(2)
        contract.issue_badge(2)
        affected = contract.suspend_node(0, "temporary lab hold")
        assert int(affected) == 3

    states = {row["node_id"]: row["state"] for row in contract.get_subtree(0)}
    assert states[0] == "SUSPENDED"
    assert states[1] == "CASCADED"
    assert states[2] == "CASCADED"
    assert len(contract.get_cascade_logs(0, 10)) == 3

    with direct_vm.prank(direct_alice):
        reinstated = contract.reinstate_node(0)
        assert int(reinstated) == 3
        revoked = contract.revoke_node(0, "residue failure at origin")
        assert revoked["affected_nodes"] == 3

    states = {row["node_id"]: row["state"] for row in contract.get_subtree(0)}
    assert states[0] == "REVOKED"
    assert states[1] == "CASCADED"
    assert states[2] == "CASCADED"
    assert contract.cert_stats()["revoked_count"] == 1
