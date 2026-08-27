import httpx
import json

# Official NIST GitHub repository raw URL for SP 800-53 Rev 5
NIST_OSCAL_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/master/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

print("-> Downloading official NIST 800-53 Rev 5 catalog from usnistgov...")
response = httpx.get(NIST_OSCAL_URL, timeout=60.0)

if response.status_code == 200:
    data = response.json()
    catalog_groups = data.get("catalog", {}).get("groups", [])
    
    indexed_controls = {}

    for group in catalog_groups:
        family_title = group.get("title", "Unknown Family")
        for control in group.get("controls", []):
            cid = control.get("id", "").upper()
            title = control.get("title", "")
            
            # Extract description / prose
            prose = ""
            for part in control.get("parts", []):
                if part.get("name") == "statement":
                    for subpart in part.get("parts", []):
                        prose += subpart.get("prose", "") + " "
                    prose += part.get("prose", "")
            
            indexed_controls[cid] = {
                "title": title,
                "family": family_title,
                "statement": prose.strip() if prose else "Standard NIST baseline requirement."
            }

    with open("nist_full_catalog.json", "w") as f:
        json.dump(indexed_controls, f, indent=2)

    print(f"✅ Successfully ingested {len(indexed_controls)} official NIST controls into nist_full_catalog.json!")
else:
    print(f"❌ Failed to download: Status {response.status_code}")
