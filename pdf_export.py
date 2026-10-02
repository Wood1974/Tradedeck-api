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
import logging
from datetime import datetime, UTC
from typing import Dict, List, Tuple
from io import BytesIO

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from PIL import Image


logger = logging.getLogger(__name__)

# Page Layout Constants
MARGIN = 1.0 * inch
COLUMN_WIDTH = 4.0 * inch
COLUMN_HEIGHT = 5.0 * inch
FOOTER_MARGIN = 0.5 * inch

# Photo Scaling Constants
PHOTO_COLUMN_RATIO = 0.9  # 90% of column width
PHOTO_HEIGHT_RATIO = 0.4  # 40% of column height

# Text Rendering Constants
CHECKPOINT_NAME_MAX_CHARS = 50
NOTE_LINE_MAX_CHARS = 50
NOTE_MAX_LINES = 3
CERT_LINE_MAX_CHARS = 80
BIND_HASH_DISPLAY_CHARS = 8

# Font Size Constants (in points)
TITLE_FONT_SIZE = 24
BODY_FONT_SIZE = 12
CHECKPOINT_FONT_SIZE = 14
NOTE_FONT_SIZE = 10
HASH_FONT_SIZE = 8

# Layout Constants (in points)
PAGE_BREAK_THRESHOLD = 200
FOOTER_CONTENT_MARGIN = 40
PHOTO_MARGIN_BOTTOM = 10
CHECKPOINT_MARGIN_BOTTOM = 25
HASH_MARGIN_BOTTOM = 20
BIND_HASH_PREFIX_MARGIN_TOP = 15

# Manifest validation constants
REQUIRED_MANIFEST_KEYS = {"checkpoint_name", "photo_bytes", "note", "bind_hash"}


def _validate_manifest(manifest: List[Dict]) -> None:
    """
    Validate manifest structure before PDF rendering.

    Args:
        manifest: List of capture dicts to validate

    Raises:
        ValueError: If manifest is invalid or entries missing required keys
    """
    if not isinstance(manifest, list):
        raise ValueError(f"Manifest must be a list, got {type(manifest).__name__}")

    for i, entry in enumerate(manifest):
        if not isinstance(entry, dict):
            raise ValueError(f"Manifest entry {i} must be a dict, got {type(entry).__name__}")

        missing_keys = REQUIRED_MANIFEST_KEYS - set(entry.keys())
        if missing_keys:
            raise ValueError(
                f"Manifest entry {i} missing required keys: {missing_keys}"
            )

        # Validate key types
        if not isinstance(entry["checkpoint_name"], str):
            raise ValueError(f"Manifest entry {i}: checkpoint_name must be string")
        if not isinstance(entry["photo_bytes"], bytes):
            raise ValueError(f"Manifest entry {i}: photo_bytes must be bytes")
        if not isinstance(entry["note"], str):
            raise ValueError(f"Manifest entry {i}: note must be string")
        if not isinstance(entry["bind_hash"], str):
            raise ValueError(f"Manifest entry {i}: bind_hash must be string")


def _wrap_text(text: str, max_line_length: int) -> List[str]:
    """
    Wrap text into multiple lines based on word boundaries.

    Args:
        text: Text to wrap
        max_line_length: Maximum characters per line

    Returns:
        List of wrapped lines
    """
    if not text:
        return []

    lines = []
    words = text.split()
    current_line = ""

    for word in words:
        test_line = current_line + " " + word if current_line else word
        if len(test_line) > max_line_length:
            if current_line:
                lines.append(current_line)
            current_line = word
        else:
            current_line = test_line

    if current_line:
        lines.append(current_line)

    return lines


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


def _scale_photo(
    photo_bytes: bytes,
    max_width: float,
    max_height: float
) -> Tuple[bytes, float, float]:
    """
    Scale photo to fit within max_width x max_height while preserving aspect ratio.

    Does not upscale photos smaller than target dimensions.

    Args:
        photo_bytes: Raw image bytes
        max_width: Maximum width in points (reportlab units)
        max_height: Maximum height in points

    Returns:
        Tuple of (scaled_image_bytes, final_width, final_height)
        On error: returns (photo_bytes, max_width, max_height)
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

        return img_bytes.getvalue(), float(new_width), float(new_height)

    except Exception as e:
        # Log failure but return valid fallback
        logger.warning(f"Failed to scale photo: {e}")
        return photo_bytes, max_width, max_height


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
    max_photo_width = col_width * PHOTO_COLUMN_RATIO
    max_photo_height = COLUMN_HEIGHT * PHOTO_HEIGHT_RATIO

    # Scale photo
    scaled_photo, photo_w, photo_h = _scale_photo(photo_bytes, max_photo_width, max_photo_height)

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
                y=y_pos - photo_h - PHOTO_MARGIN_BOTTOM,
                width=photo_w,
                height=photo_h,
                mask=None
            )
            y_pos -= photo_h + PHOTO_MARGIN_BOTTOM
    except Exception as e:
        # Log failure but continue rendering
        logger.warning(f"Failed to draw image: {e}")

    # Draw checkpoint name (bold, 14pt)
    c.setFont("Helvetica-Bold", CHECKPOINT_FONT_SIZE)
    truncated_name = checkpoint_name[:CHECKPOINT_NAME_MAX_CHARS]
    c.drawString(x + 10, y_pos - BIND_HASH_PREFIX_MARGIN_TOP, truncated_name)
    y_pos -= CHECKPOINT_MARGIN_BOTTOM

    # Draw note (italic, 10pt, word-wrapped)
    c.setFont("Helvetica-Oblique", NOTE_FONT_SIZE)
    note_lines = _wrap_text(note, NOTE_LINE_MAX_CHARS)

    for line in note_lines[:NOTE_MAX_LINES]:
        if y_pos > FOOTER_MARGIN + 100:
            c.drawString(x + 10, y_pos, line)
            y_pos -= 12

    # Draw bind_hash first 8 chars (monospace, 8pt, gray)
    c.setFont("Courier", HASH_FONT_SIZE)
    c.setFillColor(HexColor("#666666"))
    bind_hash_display = bind_hash[:BIND_HASH_DISPLAY_CHARS]
    c.drawString(x + 10, y_pos - BIND_HASH_PREFIX_MARGIN_TOP, f"bind: {bind_hash_display}")
    c.setFillColor(HexColor("#000000"))
    y_pos -= HASH_MARGIN_BOTTOM

    return y_pos


def _render_pdf_header(
    c: canvas.Canvas,
    page_width: float,
    page_height: float,
    pack_name: str,
    account_id: str,
    timestamp: str
) -> float:
    """
    Render PDF header section with pack name, timestamp, account ID.

    Returns y-position after header.
    """
    y_pos = page_height - MARGIN

    # Pack name (24pt bold, centered)
    c.setFont("Helvetica-Bold", TITLE_FONT_SIZE)
    pack_name_text = pack_name or "Capture Pack"
    c.drawCentredString(page_width / 2, y_pos, pack_name_text)
    y_pos -= 35

    # Timestamp (12pt)
    c.setFont("Helvetica", BODY_FONT_SIZE)
    c.drawCentredString(page_width / 2, y_pos, timestamp)
    y_pos -= 20

    # Account ID (12pt)
    c.drawCentredString(page_width / 2, y_pos, f"Account: {account_id}")
    y_pos -= 40

    return y_pos


def _render_photo_grid(
    c: canvas.Canvas,
    manifest: List[Dict],
    start_y: float,
    page_width: float,
    page_height: float
) -> None:
    """
    Render 2-column photo grid from manifest captures.

    Handles page breaks for large manifests.
    """
    col1_x = MARGIN
    col2_x = page_width / 2 + MARGIN / 2

    col1_y = start_y
    col2_y = start_y

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
            if col1_y < FOOTER_MARGIN + PAGE_BREAK_THRESHOLD:
                c.showPage()
                c.setFont("Helvetica", BODY_FONT_SIZE)
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
            if col2_y < FOOTER_MARGIN + PAGE_BREAK_THRESHOLD:
                c.showPage()
                c.setFont("Helvetica", BODY_FONT_SIZE)
                col1_y = page_height - MARGIN
                col2_y = page_height - MARGIN


def _render_pdf_footer(
    c: canvas.Canvas,
    manifest_hash: str,
    chain_head_hash: str
) -> None:
    """
    Render PDF footer with manifest hash, chain head hash, and certification.
    """
    footer_y = FOOTER_MARGIN + FOOTER_CONTENT_MARGIN

    # Manifest hash
    c.setFont("Courier", HASH_FONT_SIZE)
    c.drawString(MARGIN, footer_y, f"Manifest: {manifest_hash}")
    footer_y -= 12

    # Chain head hash
    c.drawString(MARGIN, footer_y, f"Chain Head: {chain_head_hash}")
    footer_y -= 12

    # Unsigned certification statement
    c.setFont("Helvetica", HASH_FONT_SIZE)
    certification = (
        "This manifest has not been cryptographically signed. "
        "Verification occurs offline using the Challenges class. "
        "Timestamp and device binding are optional."
    )
    cert_lines = _wrap_text(certification, CERT_LINE_MAX_CHARS)

    for line in cert_lines:
        c.drawString(MARGIN, footer_y, line)
        footer_y -= 10


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

    Raises:
        ValueError: If manifest structure is invalid
    """
    # Validate manifest structure
    _validate_manifest(manifest)

    # Create PDF in memory
    pdf_buffer = BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=A4)
    page_width, page_height = A4

    # Compute manifest hash (only uses metadata, not photo_bytes)
    manifest_hash = _compute_manifest_hash(manifest)

    # Get current timestamp in ISO 8601 format using UTC
    timestamp = datetime.now(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')

    # Render header
    y_pos = _render_pdf_header(c, page_width, page_height, pack_name, account_id, timestamp)

    # Render photo grid
    _render_photo_grid(c, manifest, y_pos, page_width, page_height)

    # Render footer
    _render_pdf_footer(c, manifest_hash, chain_head_hash)

    # Finalize PDF
    c.save()

    # Return PDF as bytes
    pdf_buffer.seek(0)
    return pdf_buffer.getvalue()
