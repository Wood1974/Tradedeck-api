# Shield App Icon Setup

The app icons for the Shield iOS app need to be generated before the app can be built.

## Quick Start

Run the icon generator script:

```bash
cd shield/ios
pip install Pillow
python generate_app_icon.py --color "#1f2937"
```

This generates all required icon sizes (20x20 through 1024x1024) in `Assets.xcassets/AppIcon.appiconset/`.

## What This Does

The script creates a simple icon set with the configured color. You can customize:

- `--color`: Hex color for the icon background (default: `#1f2937`, a dark gray)
- `--output`: Output directory (default: `Assets.xcassets/AppIcon.appiconset/`)

## Icon Sizes Generated

The following icon files are created:

- iPhone app icons: 20@2x, 20@3x, 29, 29@2x, 29@3x, 40@2x, 40@3x, 60@2x, 60@3x
- iPad app icons: iPad-20, iPad-20@2x, iPad-29, iPad-29@2x, iPad-40, iPad-40@2x, iPad-76, iPad-76@2x, iPad-83.5@2x
- App Store: 1024 (for marketing)

## Customizing the Icon

To use a custom icon image:

1. Create a 1024x1024 PNG image
2. Place it at `Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png`
3. Run an image resizing tool to create all the required sizes, or use the script with a custom source

## Privacy Manifest

The `Shield/PrivacyInfo.xcprivacy` file declares the app's data collection practices to Apple. It states:

- Photos are collected for app functionality only
- Device ID is linked to user identity
- No tracking is enabled
- Limited API usage for file timestamps and system boot time

This file is automatically included in the build via `project.yml`.
