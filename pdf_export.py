"""
Shield Capture PDF Export

Render capture manifests as signed PDF documents using reportlab.
Manifests carry immutable evidence chain hashes.

This module provides:
- render_manifest_pdf(): Render manifest as A4 PDF with photos, hashes, certification
- Manifest hash computation from sealed photo + note + checkpoint + bind_hash
- Photo scaling via PIL (maintains aspect ratio, fits 4" column width)
"""

import hashlib
import json
import io
from datetime import datetime
from typing import Dict, List
from io import BytesIO

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from PIL import Image


# Constants
MARGIN = 1.0 * inch
COLUMN_WIDTH = 4.0 * inch
COLUMN_HEIGHT = 5.0 * inch
PHOTO_MAX_WIDTH = COLUMN_WIDTH * 0.9  # 90% of column width
FOOTER_MARGIN = 0.5 * inch


def _compute_manifest_hash(manifest: List[Dict]) -> str:
    """
    Compute SHA-256 hash of manifest metadata (excluding photo_bytes).

    Manifest hash is reproducible from checkpoint names, notes, and bind hashes
    in the order they appear in the manifest. Photo bytes are excluded so that
    image quality/compression changes don't affect the hash.

    Args:
        manifest: List of capture dicts with checkpoint_name, note, bind_hash

    Returns:
        64-character hex SHA-256 hash
    """
    # Serialize manifest metadata (exclude photo_bytes)
    serialized = json.dumps([
        {
            "checkpoint_name": c["checkpoint_name"],
            "note": c["note"],
            "bind_hash": c["bind_hash"]
        }
        for c in manifest
    ], sort_keys=True)

    return hashlib.sha256(serialized.encode()).hexdigest()


def _scale_photo(photo_bytes: bytes, max_width: float, max_height: float) -> tuple:
    """
    Scale photo to fit within max_width x max_height while preserving aspect ratio.

    Args:
        photo_bytes: Raw image bytes
        max_width: Maximum width in points (reportlab units)
        max_height: Maximum height in points

    Returns:
        Tuple of (scaled_image_bytes, final_width, final_height)
    """
    try:
        # Load image
        img = Image.open(BytesIO(photo_bytes))

        # Get original dimensions
        orig_width, orig_height = img.size

        # Calculate scaling factor
        width_ratio = max_width / orig_width
        height_ratio = max_height / orig_height
        scale_factor = min(width_ratio, height_ratio, 1.0)  # Don't upscale

        # Calculate new dimensions
        new_width = int(orig_width * scale_factor)
        new_height = int(orig_height * scale_factor)

        # Resize image
        img_resized = img.resize((new_width, new_height), Image.Resampling.LANCZOS)

        # Convert to bytes
        img_bytes = BytesIO()
        # Determine format
        fmt = img.format or 'PNG'
        img_resized.save(img_bytes, format=fmt)
        img_bytes.seek(0)

        return img_bytes.getvalue(), new_width, new_height
    except Exception as e:
        # If image processing fails, return original
        return photo_bytes, PHOTO_MAX_WIDTH, PHOTO_MAX_WIDTH


def _draw_photo_with_metadata(
    c: canvas.Canvas,
    photo_bytes: bytes,
    checkpoint_name: str,
    note: str,
    bind_hash: str,
    x: float,
    y: float,
    col_width: float
) -> float:
    """
    Draw a photo with checkpoint name, note, and bind hash at position (x, y).

    Returns the y-position after this element (for stacking).
    """
    y_pos = y

    # Scale photo
    scaled_photo, photo_w, photo_h = _scale_photo(photo_bytes, col_width * 0.9, COLUMN_HEIGHT * 0.4)

    try:
        # Draw photo
        if scaled_photo:
            img = Image.open(BytesIO(scaled_photo))
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            img_bytes_rgb = BytesIO()
            img.save(img_bytes_rgb, format='PNG')
            img_bytes_rgb.seek(0)

            # Draw image in canvas
            c.drawImage(
                imagedata=img_bytes_rgb,
                x=x + (col_width - photo_w) / 2,
                y=y_pos - photo_h - 10,
                width=photo_w,
                height=photo_h,
                mask=None
            )
            y_pos -= photo_h + 10
    except Exception:
        # If image draw fails, skip the image
        pass

    # Draw checkpoint name (bold, 14pt)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(x + 10, y_pos - 20, checkpoint_name[:50])  # Truncate very long names
    y_pos -= 25

    # Draw note (italic, 10pt, word-wrapped)
    c.setFont("Helvetica-Oblique", 10)
    note_lines = []
    words = note.split()
    current_line = ""
    for word in words:
        test_line = current_line + " " + word if current_line else word
        if len(test_line) > 50:  # Simple word wrap at 50 chars
            if current_line:
                note_lines.append(current_line)
            current_line = word
        else:
            current_line = test_line
    if current_line:
        note_lines.append(current_line)

    for line in note_lines[:3]:  # Max 3 lines for note
        if y_pos > FOOTER_MARGIN + 100:
            c.drawString(x + 10, y_pos, line)
            y_pos -= 12

    # Draw bind_hash first 8 chars (monospace, 8pt, gray)
    c.setFont("Courier", 8)
    c.setFillColor(HexColor("#666666"))
    c.drawString(x + 10, y_pos - 15, f"bind: {bind_hash[:8]}")
    c.setFillColor(HexColor("#000000"))
    y_pos -= 20

    return y_pos


def render_manifest_pdf(
    manifest: List[Dict],
    pack_name: str,
    account_id: str,
    chain_head_hash: str
) -> bytes:
    """
    Render capture manifest as A4 PDF with immutable evidence chain hashes.

    Creates a multi-page PDF with:
    1. Header: pack name, timestamp, account ID
    2. 2-column photo grid: photos + checkpoint names + notes + bind_hash (first 8 chars)
    3. Footer: manifest SHA-256 hash, chain head hash, unsigned certification

    Manifest hash is computed from checkpoint names, notes, and bind hashes
    (photo_bytes excluded for reproducibility).

    Args:
        manifest: List of capture dicts:
            {
                "checkpoint_name": str,
                "photo_bytes": bytes,
                "note": str,
                "bind_hash": str (64-char hex)
            }
        pack_name: Display name for this capture pack
        account_id: Account/contractor ID
        chain_head_hash: Chain head hash (64-char hex SHA-256)

    Returns:
        PDF document as bytes (A4 size)
    """
    # Create PDF in memory
    pdf_buffer = BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=A4)
    page_width, page_height = A4

    # Compute manifest hash
    manifest_hash = _compute_manifest_hash(manifest)

    # Get current timestamp in ISO 8601 format
    timestamp = datetime.utcnow().isoformat() + "Z"

    # --- HEADER ---
    y_pos = page_height - MARGIN

    # Pack name (24pt bold, centered)
    c.setFont("Helvetica-Bold", 24)
    pack_name_text = pack_name or "Capture Pack"
    c.drawCentredString(page_width / 2, y_pos, pack_name_text)
    y_pos -= 35

    # Timestamp (12pt)
    c.setFont("Helvetica", 12)
    c.drawCentredString(page_width / 2, y_pos, timestamp)
    y_pos -= 20

    # Account ID (12pt)
    c.drawCentredString(page_width / 2, y_pos, f"Account: {account_id}")
    y_pos -= 40

    # --- PHOTO GRID (2 columns) ---
    col1_x = MARGIN
    col2_x = page_width / 2 + MARGIN / 2

    col1_y = y_pos
    col2_y = y_pos

    # Process captures in pairs (column 1, column 2)
    for i, capture in enumerate(manifest):
        if i % 2 == 0:  # Left column
            col1_y = _draw_photo_with_metadata(
                c,
                capture["photo_bytes"],
                capture["checkpoint_name"],
                capture["note"],
                capture["bind_hash"],
                col1_x,
                col1_y,
                COLUMN_WIDTH
            )

            # Check if we need a new page
            if col1_y < FOOTER_MARGIN + 200:
                c.showPage()
                c.setFont("Helvetica", 12)
                col1_y = page_height - MARGIN
                col2_y = page_height - MARGIN
        else:  # Right column
            col2_y = _draw_photo_with_metadata(
                c,
                capture["photo_bytes"],
                capture["checkpoint_name"],
                capture["note"],
                capture["bind_hash"],
                col2_x,
                col2_y,
                COLUMN_WIDTH
            )

            # Check if we need a new page
            if col2_y < FOOTER_MARGIN + 200:
                c.showPage()
                c.setFont("Helvetica", 12)
                col1_y = page_height - MARGIN
                col2_y = page_height - MARGIN

    # --- FOOTER ---
    footer_y = FOOTER_MARGIN + 40

    # Manifest hash
    c.setFont("Courier", 8)
    c.drawString(MARGIN, footer_y, f"Manifest: {manifest_hash}")
    footer_y -= 12

    # Chain head hash
    c.drawString(MARGIN, footer_y, f"Chain Head: {chain_head_hash}")
    footer_y -= 12

    # Unsigned certification statement
    c.setFont("Helvetica", 8)
    certification = (
        "This manifest has not been cryptographically signed. "
        "Verification occurs offline using the Challenges class. "
        "Timestamp and device binding are optional."
    )
    # Word-wrap certification
    cert_lines = []
    words = certification.split()
    current_line = ""
    for word in words:
        test_line = current_line + " " + word if current_line else word
        if len(test_line) > 80:
            if current_line:
                cert_lines.append(current_line)
            current_line = word
        else:
            current_line = test_line
    if current_line:
        cert_lines.append(current_line)

    for line in cert_lines:
        c.drawString(MARGIN, footer_y, line)
        footer_y -= 10

    # Finalize PDF
    c.save()

    # Return PDF as bytes
    pdf_buffer.seek(0)
    return pdf_buffer.getvalue()
