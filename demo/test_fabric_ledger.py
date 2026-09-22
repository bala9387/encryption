"""
demo/test_fabric_ledger.py
============================

Tests the REAL Hyperledger Fabric ledger (ledger/fabric/): 4 organisation
peers in separate containers, 3-of-4 endorsement, ML-DSA-65 signature
verification inside the chaincode, and a compromised-organisation attack.

Prerequisite:  bash ledger/fabric/network.sh up
Run:           python demo/test_fabric_ledger.py
The test restores SecurityOrg to honest mode when it finishes.
"""
import sys, os, re, json, base64, subprocess, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cv2
import numpy as np

from crypto.pqc import MLKEM, MLDSA
from crypto.document_crypto import encrypt_for_recipients
from crypto.decryption_session import perform_decryption_session
from ledger.fabric_ledger import FabricLedgerNetwork
from forensics.trace_leak import trace_leaked_document

FABRIC_DIR = os.path.join(ROOT, "ledger", "fabric")
PASS, FAIL = "✅ PASS", "❌ FAIL"
results = []


def check(name, cond, note=""):
    results.append(bool(cond))
    print(f"{PASS if cond else FAIL}  {name}" + (f"  -- {note}" if note else ""))


def set_security_org_mode(rogue_frame: str):
    """Recreates SecurityOrg's chaincode container, honest ('') or compromised."""
    env = dict(os.environ, ROGUE_FRAME=rogue_frame)
    subprocess.run(["docker", "compose", "up", "-d", "--force-recreate", "cc.security.ps26237.local"],
                   cwd=FABRIC_DIR, env=env, check=True, capture_output=True)
    time.sleep(4)


def main():
    print("=" * 90)
    print("HYPERLEDGER FABRIC LEDGER TEST -- PS 26237 (4 orgs, OutOf(3) endorsement)")
    print("=" * 90)
    ledger = FabricLedgerNetwork()

    img = np.full((256, 256, 3), 255, dtype=np.uint8)
    for y in range(20, 240, 15):
        cv2.line(img, (10, y), (200, y), (0, 0, 0), 1)

    # The ledger persists across runs and recipient keys are write-once, so each
    # run uses its own recipient IDs (alice-<run>, ...).
    run = os.urandom(3).hex()
    A, B, C = f"alice-{run}", f"bob-{run}", f"carol-{run}"
    rids = [A, B, C]
    kem = {r: MLKEM.keygen() for r in rids}
    dsa = {r: MLDSA.keygen() for r in rids}
    doc_id = f"FABRIC-TEST-{int(time.time())}"
    pkg = encrypt_for_recipients(doc_id, img.tobytes(), {r: kem[r].public_key for r in rids})

    print("\n--- Setup: recipient key registry + commits ---")
    for r in rids:
        ledger.register_recipient_key(r, dsa[r].public_key)
    rereg = ledger.invoke("RegisterRecipientKey", [A, dsa[B].public_key.hex()])
    check("Recipient keys are write-once (cannot swap alice's key for bob's)",
          not rereg.ok and "keys are write-once" in rereg.output)

    sessions, records = {}, {}
    t = time.perf_counter()
    for r in rids:
        s = perform_decryption_session(pkg, r, kem[r].secret_key, dsa[r], raw_image_array=img)
        rec = s.record.to_dict()
        rec["_signature_hex"] = s.signature_hex
        rec["_signer_public_key_hex"] = s.signer_public_key_hex
        commit = ledger.commit_record(rec)
        sessions[r], records[r] = s, rec
        check(f"{r}'s signed record committed on Fabric", commit.committed,
              f"valid at {commit.quorum_achieved}/4 peers, tx {commit.block_hash[:12]}")
    commit_ms = (time.perf_counter() - t) / len(rids) * 1000

    print("\n--- Chaincode-enforced rules (checked independently by every endorsing peer) ---")
    dup = ledger.commit_record(records[A])
    dup_out = ledger.invoke("CommitRecord", [json.dumps(records[A]), base64.b64encode(_canon(records[A])).decode()]).output
    check("Re-committing an existing watermark is rejected (immutability)",
          not dup.committed and "records are immutable" in dup_out)

    forged = dict(records[B])
    forged["watermark_id"] = os.urandom(16).hex()
    from crypto.decryption_session import DecryptionRecord
    fr = DecryptionRecord(**{k: forged[k] for k in ["watermark_id", "recipient_id", "document_id", "session_id",
                                                     "document_hash", "unix_timestamp", "human_timestamp"]})
    forged["_signature_hex"] = MLDSA.sign(fr.canonical_bytes(), dsa[A].secret_key).hex()  # alice forges bob
    forged_res = ledger.invoke("CommitRecord", [json.dumps(forged), base64.b64encode(fr.canonical_bytes()).decode()])
    check("Record naming bob but signed with alice's key is rejected (ML-DSA-65 verify in chaincode)",
          not forged_res.ok and "signature verification failed" in forged_res.output)

    swapped = dict(forged)
    swapped["_signer_public_key_hex"] = dsa[A].public_key.hex()
    swap_res = ledger.invoke("CommitRecord", [json.dumps(swapped), base64.b64encode(fr.canonical_bytes()).decode()])
    check("Record naming bob with a non-registered signer key is rejected",
          not swap_res.ok and "not the registered key" in swap_res.output)

    mismatch = dict(records[C])
    mismatch["watermark_id"] = os.urandom(16).hex()
    mm_res = ledger.invoke("CommitRecord", [json.dumps(mismatch),
                                             base64.b64encode(_canon(records[C])).decode()])
    check("Record whose fields differ from the signed payload is rejected",
          not mm_res.ok and "does not match record fields" in mm_res.output)

    print("\n--- Honest network: leak trace ---")
    integ = ledger.verify_network_integrity()
    check("All 4 peers report identical records", integ["network_consistent"],
          ", ".join(f"{n}={v.get('records')}" for n, v in integ["nodes"].items()))
    ok, enc = cv2.imencode(".jpg", sessions[C].watermarked_array, [cv2.IMWRITE_JPEG_QUALITY, 85])
    leaked = cv2.imdecode(enc, cv2.IMREAD_COLOR)
    t = time.perf_counter()
    report = trace_leaked_document(leaked, ledger, {r: dsa[r].public_key for r in rids})
    trace_ms = (time.perf_counter() - t) * 1000
    check("Leaked JPEG traced to carol via Fabric ledger", report.final_verdict.startswith("CONFIRMED")
          and report.ledger_lookup.record["recipient_id"] == C,
          f"quorum {report.ledger_lookup.quorum_achieved}/{report.ledger_lookup.quorum_needed}")

    print("\n--- Attack: SecurityOrg compromised, tries to frame bob ---")
    wm = records[C]["watermark_id"]
    try:
        set_security_org_mode(B)
        lie = json.loads(ledger.query_peer("security", "GetByWatermark", [wm]))
        check("(setup) compromised peer now reports bob for carol's watermark",
              lie["record"]["recipient_id"] == B)

        integ = ledger.verify_network_integrity()
        check("Compromised peer detected by cross-peer comparison",
              not integ["network_consistent"] and integ["tampered_nodes"] == ["security-dept-node"],
              f"tampered_nodes={integ['tampered_nodes']}")

        framed = dict(records[C])
        framed["recipient_id"] = B
        canon = base64.b64encode(_canon(records[C])).decode()
        solo = ledger.invoke("CommitRecord", [json.dumps(framed), canon], submitter="security", endorsers=["security"])
        check("Overwrite endorsed only by the compromised org is invalidated by Fabric (ENDORSEMENT_POLICY_FAILURE)",
              not solo.ok and "ENDORSEMENT_POLICY_FAILURE" in solo.output)

        allp = ledger.invoke("CommitRecord", [json.dumps(framed), canon], submitter="security")
        m = re.search(r'status:500 message:"(.*?)"', allp.output)
        check("Overwrite needing honest orgs' endorsement is refused by them",
              not allp.ok and m is not None, f"honest peer said: {m.group(1) if m else allp.output[-200:]}")

        honest_hist = [ledger.history_count(o, wm) for o in ["sender", "auditor", "backup"]]
        check("Honest peers show exactly 1 write ever for carol's watermark", honest_hist == [1, 1, 1],
              f"history counts {honest_hist}")

        report2 = trace_leaked_document(leaked, ledger, {r: dsa[r].public_key for r in rids})
        check("Trace still CONFIRMS carol (compromised peer outvoted 3-1)",
              report2.final_verdict.startswith("CONFIRMED") and report2.ledger_lookup.record["recipient_id"] == C,
              f"agreeing: {report2.ledger_lookup.node_ids_matched}")
    finally:
        set_security_org_mode("")
    check("After restoring SecurityOrg, all 4 peers agree again", ledger.verify_network_integrity()["network_consistent"])

    print("\n--- Measured timings (this machine, Docker Desktop, peer CLI via docker exec) ---")
    print(f"  commit (endorse on 4 peers + order + validate): {commit_ms:.0f} ms per record")
    print(f"  forensic trace (extract + 4 peer queries + ML-DSA verify): {trace_ms:.0f} ms")

    print("\n" + "=" * 90)
    print(f"SCORE: {sum(results)}/{len(results)} Fabric ledger checks passed")
    print("=" * 90)
    sys.exit(0 if all(results) else 1)


def _canon(rec: dict) -> bytes:
    from crypto.decryption_session import DecryptionRecord
    return DecryptionRecord(**{k: rec[k] for k in ["watermark_id", "recipient_id", "document_id", "session_id",
                                                    "document_hash", "unix_timestamp", "human_timestamp"]}).canonical_bytes()


if __name__ == "__main__":
    main()
