"""Material identification for checkpoint photos.

This file owns the trade vocabulary, the schema fields the vision call returns,
and the prompt text for material identification. vision.py imports them and
does not define them. To add a trade, add an entry to TRADE_MATERIALS. Do not
edit vision.py.

Trades in this first batch: electrical, plumbing, framing, roofing, concrete.
Batch two is added here as further TRADE_MATERIALS entries.

Every answer here is about pixels. Nothing in this file reads the request or
the uploader's description (see routes.analyze_photo and the invariant in
shield/audit/invariants.py).
"""

TRADE_MATERIALS = {
    "electrical": [
        "NM-B cable (Romex), sheathed, with visible conductor colours",
        "EMT or PVC conduit and fittings",
        "metal or plastic electrical boxes, with cable clamps",
        "panel and breakers, including AFCI and GFCI breakers",
        "GFCI and AFCI receptacles and devices",
        "grounding electrode conductor and clamps",
        "copper or aluminium conductor, identifiable by gauge markings or insulation",
    ],
    "plumbing": [
        "PEX tubing, in red, blue or white, with crimp or expansion fittings",
        "copper pipe, sweat or press fittings",
        "CPVC pipe, cream or tan",
        "PVC or ABS drain, waste and vent pipe (DWV), white or black",
        "cast iron soil pipe and hubs",
        "shutoff valves, angle stops, and supply lines",
        "water heater, with temperature-pressure relief valve and expansion tank",
    ],
    "framing": [
        "dimensional lumber (SPF or Douglas fir), with grade stamps",
        "engineered lumber: LVL, I-joists, glulam beams",
        "OSB or plywood wall and floor sheathing, with span rating",
        "steel stud and track, gauge-stamped",
        "metal joist hangers and connectors (Simpson-type hardware)",
        "hold-down straps and anchor bolts",
        "built-up headers and beams",
    ],
    "roofing": [
        "asphalt shingles, laminated or three-tab",
        "synthetic or felt underlayment",
        "ice-and-water shield at eaves and valleys",
        "metal drip edge",
        "metal flashing at penetrations, valleys and walls",
        "roof decking: OSB or plywood, with sheathing clips",
        "ridge vent and ridge cap",
    ],
    "concrete": [
        "ready-mix concrete, fresh or cured, with visible finish",
        "rebar (#4 or #5), with mill marks, tied at spacing",
        "welded wire mesh",
        "vapor barrier or polyethylene sheeting under slab",
        "anchor bolts and embedded plates",
        "form boards and stakes",
        "fiber mesh or admixture evident in finish",
    ],
}

TRADES = tuple(TRADE_MATERIALS) + ("other", "unknown")

# Merged into the analysis schema in vision.py. Kept here so the material fields
# can change without touching the verdict schema.
MATERIAL_SCHEMA_PROPERTIES = {
    "material_trade":        {"type": "string", "enum": list(TRADES)},
    "materials_identified":  {"type": "array", "items": {"type": "string"}},
    "material_matches_spec": {"type": ["boolean", "null"]},
    "material_note":         {"type": "string"},
}
MATERIAL_SCHEMA_REQUIRED = list(MATERIAL_SCHEMA_PROPERTIES)


def materials_brief() -> str:
    """Prompt text: what to identify, per trade, and how to report it."""
    lines = [
        "3. MATERIALS. Identify the trade and the materials actually visible in the "
        "frame. Use only these trade categories:",
    ]
    for trade, items in TRADE_MATERIALS.items():
        lines.append(f"- {trade}:")
        lines.extend(f"    * {item}" for item in items)
    lines.append(
        "Report material_trade as one of the trades above, or 'other' if the photo "
        "shows a trade not listed, or 'unknown' if the frame is too unclear to tell. "
        "List each material you can see in materials_identified, in plain words. "
        "Set material_matches_spec to true if the visible materials are the ones the "
        "checkpoint requires, false if they are clearly not, and null if the frame "
        "does not show enough to tell. Do not guess a material you cannot see."
    )
    return "\n".join(lines)
