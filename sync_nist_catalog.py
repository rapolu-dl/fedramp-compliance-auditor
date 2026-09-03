import hashlib
import json
import os
from pathlib import Path

import httpx

# Pin the NIST OSCAL source for reproducibility.
# Override with NIST_OSCAL_REF if you intentionally want a newer official revision.
NIST_OSCAL_REF = os.getenv(
    "NIST_OSCAL_REF",
    "78650f02ad9321bb7b817846f8fbd4f2bcd620de",
)

NIST_OSCAL_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/"
    f"{NIST_OSCAL_REF}/nist.gov/SP800-53/rev5/json/"
    "NIST_SP-800-53_rev5_catalog.json"
)

CATALOG_OUTPUT = Path("nist_full_catalog.json")
METADATA_OUTPUT = Path("nist_catalog_metadata.json")


def collect_part_prose(parts):
    """Recursively collect prose from OSCAL parts."""
    text = []

    def walk(part):
        prose = part.get("prose")
        if prose:
            text.append(prose.strip())

        for child in part.get("parts", []):
            walk(child)

    for part in parts or []:
        walk(part)

    return " ".join(text).strip()


def extract_statement(control):
    """Extract the full statement for a control or enhancement."""
    statement_parts = [
        part
        for part in control.get("parts", [])
        if part.get("name") == "statement"
    ]

    return collect_part_prose(statement_parts)


def get_status(control):
    """Return OSCAL status such as active or withdrawn."""
    for prop in control.get("props", []):
        if prop.get("name") == "status":
            return str(prop.get("value", "")).strip().lower()

    return "active"


def index_controls(
    controls,
    indexed_controls,
    counts,
    family_id,
    family_title,
    parent_control=None,
):
    """
    Recursively index:
    - base controls
    - control enhancements
    """

    for control in controls or []:
        raw_id = str(control.get("id", "")).strip()

        if not raw_id:
            counts["missing_id"] += 1
            continue

        control_id = raw_id.upper()

        if control_id in indexed_controls:
            raise ValueError(
                f"Duplicate NIST control ID encountered: {control_id}"
            )

        status = get_status(control)
        is_enhancement = parent_control is not None

        indexed_controls[control_id] = {
            "id": control_id,
            "source_id": raw_id,
            "title": control.get("title", ""),
            "family": family_title,
            "family_id": family_id,
            "parent_control": parent_control,
            "is_enhancement": is_enhancement,
            "status": status,
            "withdrawn": status == "withdrawn",
            "statement": extract_statement(control),

            # Preserve official OSCAL structures for later use
            "params": control.get("params", []),
            "props": control.get("props", []),
            "links": control.get("links", []),
        }

        if is_enhancement:
            counts["enhancements"] += 1
        else:
            counts["base_controls"] += 1

        if status == "withdrawn":
            counts["withdrawn"] += 1

        # IMPORTANT:
        # OSCAL control enhancements are nested inside "controls".
        index_controls(
            control.get("controls", []),
            indexed_controls,
            counts,
            family_id,
            family_title,
            parent_control=control_id,
        )


def index_groups(groups, indexed_controls, counts):
    """Walk all catalog groups/families."""

    for group in groups or []:
        family_id = str(group.get("id", "")).strip().upper()
        family_title = group.get("title", "Unknown Family")

        index_controls(
            group.get("controls", []),
            indexed_controls,
            counts,
            family_id,
            family_title,
        )

        # Defensive support if future OSCAL content nests groups
        index_groups(
            group.get("groups", []),
            indexed_controls,
            counts,
        )


def main():
    print("-> Downloading official NIST SP 800-53 Rev 5 OSCAL catalog...")
    print(f"-> Source ref: {NIST_OSCAL_REF}")

    response = httpx.get(
        NIST_OSCAL_URL,
        timeout=60.0,
        follow_redirects=True,
    )

    response.raise_for_status()

    source_sha256 = hashlib.sha256(
        response.content
    ).hexdigest()

    data = response.json()

    catalog = data.get("catalog")

    if not catalog:
        raise ValueError(
            "Downloaded document does not contain an OSCAL catalog object."
        )

    indexed_controls = {}

    counts = {
        "base_controls": 0,
        "enhancements": 0,
        "withdrawn": 0,
        "missing_id": 0,
    }

    index_groups(
        catalog.get("groups", []),
        indexed_controls,
        counts,
    )

    # Prevent the old 324-control bug from silently returning.
    if counts["enhancements"] == 0:
        raise RuntimeError(
            "No control enhancements were indexed. "
            "Refusing to write an incomplete catalog."
        )

    # Simple sanity check proving recursion worked.
    # OSCAL represents AC-2(1) as ac-2.1.
    if "AC-2.1" not in indexed_controls:
        raise RuntimeError(
            "Expected enhancement AC-2.1 was not found. "
            "Catalog ingestion appears incomplete."
        )

    metadata = catalog.get("metadata", {})

    provenance = {
        "source": "NIST OSCAL content repository",
        "source_url": NIST_OSCAL_URL,
        "source_ref": NIST_OSCAL_REF,
        "source_sha256": source_sha256,

        "catalog_title": metadata.get("title"),
        "catalog_version": metadata.get("version"),
        "oscal_version": metadata.get("oscal-version"),
        "last_modified": metadata.get("last-modified"),

        "base_controls": counts["base_controls"],
        "control_enhancements": counts["enhancements"],
        "withdrawn_entries": counts["withdrawn"],
        "missing_id_entries": counts["missing_id"],
        "total_indexed": len(indexed_controls),
    }

    with CATALOG_OUTPUT.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            indexed_controls,
            f,
            indent=2,
            ensure_ascii=False,
        )

    with METADATA_OUTPUT.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            provenance,
            f,
            indent=2,
            ensure_ascii=False,
        )

    print()
    print("✅ NIST catalog ingestion complete")
    print(
        f"   Base controls:        "
        f"{counts['base_controls']}"
    )
    print(
        f"   Control enhancements: "
        f"{counts['enhancements']}"
    )
    print(
        f"   Withdrawn entries:    "
        f"{counts['withdrawn']}"
    )
    print(
        f"   Total indexed:        "
        f"{len(indexed_controls)}"
    )
    print(
        f"   Catalog SHA-256:      "
        f"{source_sha256}"
    )
    print(
        f"   Wrote: {CATALOG_OUTPUT}"
    )
    print(
        f"   Wrote: {METADATA_OUTPUT}"
    )


if __name__ == "__main__":
    main()