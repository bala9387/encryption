"""
demo/test_watermark_robustness.py
===================================

Measures watermark survival (bit error rate, exact recovery, and ledger
attribution distance) across realistic leak transformations, on:
  - the synthetic line-pattern test image used elsewhere in the project,
  - a real PDF page (text, headings, table rules) rendered at 150 DPI,
  - 6 real scanned business forms from the FUNSD dataset (testdata/scans/,
    https://guillaumejaume.github.io/FUNSD/ -- research/non-commercial use).

Nothing here is asserted: every number is measured and printed. Results are
also written to output/watermark_robustness.json.

Run: python demo/test_watermark_robustness.py [--quick]
"""
import sys, os, json, time, glob, argparse
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cv2
import numpy as np

from watermark.dct_watermark import embed_watermark, extract_watermark, bit_error_rate

ATTRIBUTION_MAX_BER = 16 / 128   # forensics accepts a ledger match within 16 bits (see forensics/trace_leak.py)


# ---------------------------------------------------------------- test images
def synthetic():
    img = np.full((512, 512, 3), 255, np.uint8)
    for y in range(20, 500, 15):
        cv2.line(img, (10, y), (400, y), (0, 0, 0), 1)
    return img


def pdf_render():
    import pymupdf
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)  # A4 points
    page.insert_text((60, 70), "RESTRICTED -- OPERATIONAL ANNEX C", fontsize=16, fontname="hebo")
    body = ("The task group will proceed to the designated area and maintain station keeping "
            "within the assigned sector. Communications will follow the schedule in Appendix 2. ")
    y = 110
    for para in range(6):
        rect = pymupdf.Rect(60, y, 535, y + 90)
        page.insert_textbox(rect, body * 2, fontsize=10, fontname="helv")
        y += 100
    for i in range(6):
        page.draw_line((60, 720 + i * 16), (535, 720 + i * 16), width=0.6)
    for x in (60, 220, 380, 535):
        page.draw_line((x, 720), (x, 800), width=0.6)
    pix = page.get_pixmap(dpi=150, colorspace=pymupdf.csRGB, alpha=False)
    arr = np.frombuffer(pix.samples, np.uint8).reshape(pix.height, pix.width, 3)
    return cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)


def scans(limit):
    files = sorted(glob.glob(os.path.join(ROOT, "testdata", "scans", "*.png")))[:limit]
    return [(os.path.basename(f), cv2.imread(f, cv2.IMREAD_COLOR)) for f in files]


# ---------------------------------------------------------------- attacks
RNG = np.random.default_rng(12345)


def jpeg(img, q):
    ok, enc = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, q])
    return cv2.imdecode(enc, cv2.IMREAD_COLOR)


def noise(img, sigma):
    return np.clip(img + RNG.normal(0, sigma, img.shape), 0, 255).astype(np.uint8)


def crop(img, top=0.0, bottom=0.0, left=0.0, right=0.0):
    h, w = img.shape[:2]
    return img[int(h * top): h - int(h * bottom), int(w * left): w - int(w * right)].copy()


def scale(img, s):
    h, w = img.shape[:2]
    return cv2.resize(img, (round(w * s), round(h * s)), interpolation=cv2.INTER_AREA if s < 1 else cv2.INTER_CUBIC)


def rotate(img, deg):
    h, w = img.shape[:2]
    m = cv2.getRotationMatrix2D((w / 2, h / 2), deg, 1.0)
    return cv2.warpAffine(img, m, (w, h), flags=cv2.INTER_CUBIC, borderValue=(255, 255, 255))


def print_scan(img):
    """Simulated print -> flatbed scan: slight skew and scale change, optical
    blur, paper/toner contrast loss and gamma, sensor noise, JPEG from the scanner."""
    out = rotate(img, 1.2)
    out = scale(out, 0.97)
    out = cv2.GaussianBlur(out, (0, 0), 0.9)
    f = out.astype(np.float32) / 255.0
    f = 0.06 + 0.88 * np.power(f, 1.15)
    out = np.clip(f * 255 + RNG.normal(0, 3.5, f.shape), 0, 255).astype(np.uint8)
    return jpeg(out, 85)


def screen_photo(img):
    """Simulated phone photo of a screen: perspective distortion, downscale,
    moire, uneven brightness, blur, noise, phone JPEG."""
    h, w = img.shape[:2]
    d = 0.03
    src = np.float32([[0, 0], [w, 0], [w, h], [0, h]])
    dst = np.float32([[w * d, h * d * 0.5], [w * (1 - d * 0.4), 0], [w, h * (1 - d)], [0, h]])
    out = cv2.warpPerspective(img, cv2.getPerspectiveTransform(src, dst), (w, h), flags=cv2.INTER_CUBIC,
                              borderValue=(255, 255, 255))
    out = scale(out, 0.8)
    hh, ww = out.shape[:2]
    yy, xx = np.mgrid[0:hh, 0:ww]
    moire = 6 * np.sin(2 * np.pi * (xx * 0.21 + yy * 0.07))
    light = 1.0 - 0.12 * ((xx - ww * 0.7) ** 2 + (yy - hh * 0.3) ** 2) / (ww ** 2 + hh ** 2)
    f = out.astype(np.float32) * light[..., None] + moire[..., None]
    out = cv2.GaussianBlur(np.clip(f, 0, 255).astype(np.uint8), (0, 0), 1.1)
    return jpeg(noise(out, 4), 80)


ATTACKS = [
    ("baseline: lossless", lambda i: i),
    ("jpeg q90", lambda i: jpeg(i, 90)),
    ("jpeg q75", lambda i: jpeg(i, 75)),
    ("jpeg q60", lambda i: jpeg(i, 60)),
    ("jpeg q50", lambda i: jpeg(i, 50)),
    ("gaussian noise sigma=5", lambda i: noise(i, 5)),
    ("crop: header 10% removed", lambda i: crop(i, top=0.10)),
    ("crop: footer 15% removed", lambda i: crop(i, bottom=0.15)),
    ("crop: 3px off left+top (grid misalignment)", lambda i: i[3:, 3:]),
    ("crop: centre 50% only", lambda i: crop(i, 0.25, 0.25, 0.25, 0.25)),
    ("rescale x0.5", lambda i: scale(i, 0.5)),
    ("rescale x0.75", lambda i: scale(i, 0.75)),
    ("rescale x0.9", lambda i: scale(i, 0.9)),
    ("rescale x1.25", lambda i: scale(i, 1.25)),
    ("rescale x2.0", lambda i: scale(i, 2.0)),
    ("rotate 1 deg", lambda i: rotate(i, 1)),
    ("rotate 2 deg", lambda i: rotate(i, 2)),
    ("rotate 3 deg", lambda i: rotate(i, 3)),
    ("rotate 5 deg", lambda i: rotate(i, 5)),
    ("rotate 2 deg + jpeg q75", lambda i: jpeg(rotate(i, 2), 75)),
    ("crop header + rescale x0.8 + jpeg q75", lambda i: jpeg(scale(crop(i, top=0.1), 0.8), 75)),
    ("print-and-scan simulation", print_scan),
    ("photo-of-screen simulation", screen_photo),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="2 scans instead of 6")
    ap.add_argument("--label", default="current")
    args = ap.parse_args()

    images = [("synthetic 512x512", synthetic()), ("PDF page render 150dpi", pdf_render())]
    images += [(f"scan {n}", im) for n, im in scans(2 if args.quick else 6)]

    wm = bytes.fromhex("9ab81eb952eb238d3bcd43cf823fc565")
    results = {"label": args.label, "images": {}, "attacks": {}}
    t_extract = []
    print(f"Watermark robustness -- algorithm: {args.label}")
    for name, img in images:
        marked, _ = embed_watermark(img, wm)
        diff = np.abs(marked.astype(int) - img.astype(int))
        psnr = cv2.PSNR(img, marked)
        results["images"][name] = {"shape": list(img.shape), "psnr_db": round(psnr, 2),
                                   "mean_abs_diff": round(float(diff.mean()), 3), "max_abs_diff": int(diff.max())}
        print(f"\n{name} {img.shape[1]}x{img.shape[0]}: PSNR {psnr:.1f} dB, mean |diff| {diff.mean():.3f}, max {diff.max()}")
        for aname, fn in ATTACKS:
            attacked = fn(marked)
            t = time.perf_counter()
            rec = extract_watermark(attacked)
            t_extract.append(time.perf_counter() - t)
            ber = bit_error_rate(wm, rec)
            results["attacks"].setdefault(aname, {})[name] = round(float(ber), 4)
            print(f"   {aname:45s} BER {ber:.3f}  {'exact' if ber == 0 else ('attributable' if ber <= ATTRIBUTION_MAX_BER else 'LOST')}")

    print("\n" + "=" * 100)
    print(f"SUMMARY ({len(images)} images; 'attributable' = BER <= {ATTRIBUTION_MAX_BER:.3f}, i.e. <= 16 of 128 bits wrong)")
    print("=" * 100)
    print(f"{'attack':45s} {'exact':>7s} {'attrib.':>8s} {'mean BER':>9s} {'worst BER':>10s}")
    summary = {}
    for aname, _ in ATTACKS:
        bers = list(results["attacks"][aname].values())
        exact = sum(b == 0 for b in bers)
        attrib = sum(b <= ATTRIBUTION_MAX_BER for b in bers)
        summary[aname] = {"exact": exact, "attributable": attrib, "n": len(bers),
                          "mean_ber": round(float(np.mean(bers)), 4), "worst_ber": round(float(np.max(bers)), 4)}
        print(f"{aname:45s} {exact:>4d}/{len(bers)} {attrib:>5d}/{len(bers)} {np.mean(bers):>9.3f} {np.max(bers):>10.3f}")
    results["summary"] = summary
    results["extract_seconds_mean"] = round(float(np.mean(t_extract)), 3)
    results["extract_seconds_max"] = round(float(np.max(t_extract)), 3)
    print(f"\nextraction time: mean {np.mean(t_extract):.2f}s, max {np.max(t_extract):.2f}s")

    os.makedirs(os.path.join(ROOT, "output"), exist_ok=True)
    with open(os.path.join(ROOT, "output", f"watermark_robustness_{args.label}.json"), "w") as f:
        json.dump(results, f, indent=1)


if __name__ == "__main__":
    main()
