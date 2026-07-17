"""OCR all screenshots in ss/ and write per-image text + a combined report."""
from pathlib import Path
import easyocr
import json

BASE = Path(__file__).resolve().parent
SS = BASE / "ss"
OUT = BASE / "ss_ocr"
OUT.mkdir(exist_ok=True)

reader = easyocr.Reader(["en"], gpu=False, verbose=False)

results = {}
for img in sorted(SS.glob("*.png")):
    print(f"\n=== {img.name} ===")
    # use_grain=False for screenshots; paragraph=True to group text lines
    detections = reader.readtext(str(img), detail=1, paragraph=True)
    lines = []
    for det in detections:
        # paragraph mode returns a single tuple per region: (bbox, text)
        bbox, text = det
        lines.append({"bbox": [[float(x) for x in pt] for pt in bbox], "text": text})
    results[img.name] = lines
    out_file = OUT / (img.stem + ".txt")
    with out_file.open("w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln["text"] + "\n")
    print(f"  -> {out_file.name} ({len(lines)} blocks)")

with (OUT / "all.json").open("w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)
print(f"\nWrote combined JSON to {OUT/'all.json'}")
