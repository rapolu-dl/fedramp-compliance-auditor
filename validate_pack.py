import json
from pathlib import Path
from collections import Counter

root = Path(__file__).resolve().parent
test_dir = root / "test_cases"
files = sorted(test_dir.glob("*.json"))

required = {"id", "test_name", "architecture", "expected_status", "expected_risk"}
status = Counter()
risk = Counter()
ids = set()

for p in files:
    data = json.loads(p.read_text(encoding="utf-8"))
    missing = required - set(data)
    if missing:
        raise ValueError(f"{p.name}: missing {sorted(missing)}")
    if data["id"] in ids:
        raise ValueError(f"Duplicate id: {data['id']}")
    ids.add(data["id"])
    status[data["expected_status"]] += 1
    risk[data["expected_risk"]] += 1

print(f"Valid JSON files: {len(files)}")
print("Status distribution:", dict(status))
print("Risk distribution:", dict(risk))
