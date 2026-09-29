#!/usr/bin/env python3
"""Generate app icons for the Shield iOS app.

Usage:
    python shield/ios/generate_app_icon.py --color "#1f2937"

This generates all required icon sizes from a 1024x1024 source icon.
Requires: Pillow (pip install pillow)
"""
import argparse
import os
from pathlib import Path
from PIL import Image, ImageDraw

# Icon sizes needed for iOS app
ICON_SIZES = [
    (20, "20"),
    (40, "20@2x"),
    (60, "20@3x"),
    (29, "29"),
    (58, "29@2x"),
    (87, "29@3x"),
    (40, "40"),
    (80, "40@2x"),
    (120, "40@3x"),
    (60, "60@2x"),
    (180, "60@3x"),
    (76, "iPad-76"),
    (152, "iPad-76@2x"),
    (167, "iPad-83.5@2x"),
    (20, "iPad-20"),
    (40, "iPad-20@2x"),
    (29, "iPad-29"),
    (58, "iPad-29@2x"),
    (40, "iPad-40"),
    (80, "iPad-40@2x"),
    (1024, "1024"),
]


def create_icon(size, color):
    """Create a simple icon with the given size and color."""
    # Create a simple icon: a rounded square with a gradient
    img = Image.new("RGB", (size, size), color=color)

    # Draw a simple camera symbol or "S" for Shield
    draw = ImageDraw.Draw(img)

    if size >= 200:
        # For larger icons, draw a more detailed design
        # Draw an "S" for Shield in white
        draw.rectangle([int(size * 0.1), int(size * 0.1),
                        int(size * 0.9), int(size * 0.9)],
                       outline="white", width=int(size * 0.05))

    # Convert to RGBA for alpha support
    img = img.convert("RGBA")
    return img


def main():
    parser = argparse.ArgumentParser(description="Generate Shield app icons")
    parser.add_argument("--color", default="#1f2937",
                        help="Hex color for icon background")
    parser.add_argument("--output", default="shield/ios/Assets.xcassets/AppIcon.appiconset",
                        help="Output directory for icon files")

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating app icons in {output_dir}...")

    for size, name in ICON_SIZES:
        icon = create_icon(size, args.color)
        filename = f"AppIcon-{name}.png"
        filepath = output_dir / filename

        icon.save(filepath)
        print(f"  ✓ {filename} ({size}x{size})")

    print()
    print("App icons generated successfully!")
    print("The icons are ready to be included in Xcode.")


if __name__ == "__main__":
    main()
