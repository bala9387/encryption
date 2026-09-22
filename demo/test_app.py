"""
demo/test_app.py
==================

End-to-end test of the application layer (CLI / web service layer):
identity creation, encrypt-once, per-recipient decrypt, PDF support,
leak tracing, and the rules that protect the workflow.

Runs against the simulated ledger in a temporary workspace (no Docker).
Run: python demo/test_app.py
"""
import sys, os, io, json, shutil, tempfile, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cv2
import numpy as np
import pymupdf

from app.service import Workspace, ServiceError
from watermark.document_formats import UnsupportedFormat, detect_format

PASS, FAIL = "✅ PASS", "❌ FAIL"
results = []
PASSPHRASE = "test-passphrase-123"


def check(name, cond, note=""):
    results.append(bool(cond))
    print(f"{PASS if cond else FAIL}  {name}" + (f"  -- {note}" if note else ""))


def raises(fn, needle: str) -> bool:
    try:
        fn()
        return False
    except (ServiceError, UnsupportedFormat) as e:
        return needle.lower() in str(e).lower()


def make_pdf(pages=2) -> bytes:
    d = pymupdf.open()
    for n in range(pages):
        p = d.new_page(width=595, height=842)
        p.insert_text((60, 70), f"RESTRICTED -- ANNEX C -- PAGE {n + 1}", fontsize=16, fontname="hebo")
        y = 110
        for _ in range(5):
            p.insert_textbox(pymupdf.Rect(60, y, 535, y + 95),
                             "The task group will proceed to the designated area and maintain station "
                             "keeping within the assigned sector. " * 3, fontsize=10, fontname="helv")
            y += 105
    return d.tobytes()


def main():
    print("=" * 90)
    print("APPLICATION LAYER TEST -- PS 26237 (CLI / web service layer, simulated ledger)")
    print("=" * 90)
    tmp = tempfile.mkdtemp(prefix="ps26237-test-")
    try:
        ws = Workspace(os.path.join(tmp, "workspace"), ledger="sim")

        print("\n--- Identities ---")
        for rid in ["alice", "bob", "carol"]:
            ws.create_identity(rid, PASSPHRASE)
        info = ws.public_identity("alice")
        check("Identity holds real ML-KEM-768 + ML-DSA-65 public keys",
              info["kem_public_key_bytes"] == 1184 and info["dsa_public_key_bytes"] == 1952,
              info["algorithms"]["backend"])
        check("Duplicate identity is refused", raises(lambda: ws.create_identity("alice", PASSPHRASE), "already exists"))
        check("Weak passphrase is refused", raises(lambda: ws.create_identity("dan", "short"), "at least 8"))
        check("Secret keys are encrypted at rest (passphrase-derived AES-256-GCM)",
              b"scrypt" in open(os.path.join(ws.root, "identities", "alice.json"), "rb").read())

        print("\n--- Encrypt once, decrypt individually (image) ---")
        img = cv2.imread(os.path.join(ROOT, "testdata", "scans", "82092117.png"))
        ok, enc = cv2.imencode(".png", img)
        doc = enc.tobytes()
        pkg = ws.encrypt(doc, "memo.png", ["alice", "bob", "carol"], "APP-TEST-DOC")
        meta = ws.package_info(pkg)
        check("One shared ciphertext with one key wrap per recipient",
              meta["recipients"] == ["alice", "bob", "carol"] and meta["ciphertext_bytes"] > len(doc) - 100)

        outs, t0 = {}, time.perf_counter()
        for rid in ["alice", "bob", "carol"]:
            outs[rid] = ws.decrypt(pkg, rid, PASSPHRASE)
        decrypt_ms = (time.perf_counter() - t0) / 3 * 1000
        wms = {r: o.record["watermark_id"] for r, o in outs.items()}
        check("Each recipient gets a different watermark", len(set(wms.values())) == 3)
        again = ws.decrypt(pkg, "alice", PASSPHRASE)
        check("Same recipient decrypting twice gets a new watermark", again.record["watermark_id"] != wms["alice"])

        a = cv2.imdecode(np.frombuffer(outs["alice"].data, np.uint8), cv2.IMREAD_COLOR)
        b = cv2.imdecode(np.frombuffer(outs["bob"].data, np.uint8), cv2.IMREAD_COLOR)
        mean_diff = float(np.abs(a.astype(int) - b.astype(int)).mean())
        psnr = cv2.PSNR(img, a)
        check("Copies are visually identical to each other (mean pixel diff < 2)", mean_diff < 2.0,
              f"mean diff {mean_diff:.3f}, PSNR vs original {psnr:.1f} dB")

        check("Unknown recipient cannot decrypt", raises(lambda: ws.decrypt(pkg, "dan", PASSPHRASE), "unknown identity"))
        check("Wrong passphrase cannot decrypt", raises(lambda: ws.decrypt(pkg, "bob", "wrong-passphrase"), "wrong passphrase"))
        pkg_no_carol = ws.encrypt(doc, "memo.png", ["alice", "bob"])
        check("Recipient not in the package is refused",
              raises(lambda: ws.decrypt(pkg_no_carol, "carol", PASSPHRASE), "not an authorized recipient"))
        check("Office documents are refused with conversion advice",
              raises(lambda: ws.encrypt(b"PK\x03\x04fake docx", "x.docx", ["alice"]), "convert to PDF"))

        print("\n--- Ledger binding ---")
        status = ws.ledger_status()
        check("Every decryption is committed to the ledger", status["records"] == 4,
              f"{status['records']} records on {len(status['nodes'])} nodes, quorum {status['quorum']}")
        check("All ledger nodes agree", status["integrity"]["network_consistent"])
        rec = outs["carol"].record
        check("Record binds watermark to recipient, document, session and time",
              rec["recipient_id"] == "carol" and rec["document_id"] == "APP-TEST-DOC"
              and len(rec["watermark_id"]) == 32 and rec["session_id"] and rec["human_timestamp"])

        print("\n--- Forensic trace (image) ---")
        leaked = cv2.resize(a[90:, :], None, fx=0.8, fy=0.8, interpolation=cv2.INTER_AREA)
        ok, jpg = cv2.imencode(".jpg", leaked, [cv2.IMWRITE_JPEG_QUALITY, 75])
        t0 = time.perf_counter()
        tr = ws.trace(jpg.tobytes())
        trace_s = time.perf_counter() - t0
        check("Cropped + rescaled + JPEG leak traced to the right recipient",
              tr.confirmed and tr.report.ledger_lookup.record["recipient_id"] == "alice",
              f"{tr.report.match_distance_bits} bits differ, {trace_s:.0f}s")
        check("Recipient's own ML-DSA-65 signature verifies at trace time", tr.report.signature_valid is True)
        check("Quorum of nodes agree on the record",
              tr.report.ledger_lookup.verified and tr.report.ledger_lookup.quorum_achieved >= 3)

        unmarked = ws.trace(doc)
        check("An unwatermarked document is reported as NO MATCH, not attributed",
              not unmarked.confirmed and not unmarked.report.ledger_lookup.found)

        print("\n--- PDF support ---")
        pdf = make_pdf(2)
        pdf_pkg = ws.encrypt(pdf, "annex.pdf", ["alice", "bob"], "APP-TEST-PDF")
        pdf_out = ws.decrypt(pdf_pkg, "bob", PASSPHRASE)
        d = pymupdf.open(stream=pdf_out.data, filetype="pdf")
        src = pymupdf.open(stream=pdf, filetype="pdf")
        check("Watermarked PDF keeps page count and page size", d.page_count == src.page_count
              and abs(d[0].rect.width - src[0].rect.width) < 1,
              f"{len(pdf_out.data) / 1e6:.2f} MB for {d.page_count} pages ({len(pdf) / 1e3:.1f} kB source)")
        check("PDF pages are rasterised (no copyable text layer left unwatermarked)",
              d[0].get_text().strip() == "")
        pdf_trace = ws.trace(pdf_out.data)
        check("Leaked PDF traced to the right recipient",
              pdf_trace.confirmed and pdf_trace.report.ledger_lookup.record["recipient_id"] == "bob",
              f"from {pdf_trace.source}")

        pix = d[1].get_pixmap(dpi=110)
        page_img = cv2.cvtColor(np.frombuffer(pix.samples, np.uint8).reshape(pix.height, pix.width, 3), cv2.COLOR_RGB2BGR)
        ok, shot = cv2.imencode(".jpg", page_img[60:-40, 30:-20], [cv2.IMWRITE_JPEG_QUALITY, 80])
        t0 = time.perf_counter()
        shot_trace = ws.trace(shot.tobytes())
        check("Screenshot of one PDF page (110 dpi, cropped, JPEG) traced to the right recipient",
              shot_trace.confirmed and shot_trace.report.ledger_lookup.record["recipient_id"] == "bob",
              f"{shot_trace.report.match_distance_bits} bits differ, {time.perf_counter() - t0:.0f}s")

        print("\n--- Persistence ---")
        before = ws.ledger_status()["records"]
        ws2 = Workspace(ws.root)
        after = ws2.ledger_status()
        check("Workspace reloads identities and ledger from disk",
              ws2.list_identities() == ["alice", "bob", "carol"] and after["records"] == before
              and after["integrity"]["network_consistent"],
              f"{after['records']} records, {len(ws2.list_identities())} identities reloaded")

        print(f"\nTimings: decrypt+watermark+sign+commit {decrypt_ms:.0f} ms/recipient (image), "
              f"trace {trace_s:.1f} s (geometric search)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 90)
    print(f"SCORE: {sum(results)}/{len(results)} application checks passed")
    print("=" * 90)
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
