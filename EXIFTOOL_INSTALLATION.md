# ExifTool Installation Guide for MetaForensicAI

MetaForensicAI uses **ExifTool** for high-fidelity metadata extraction when available. The system will automatically detect and use ExifTool if installed, or fall back to Python-based extraction.

## Why ExifTool?

- **Industry Standard**: ExifTool is the gold standard for forensic metadata extraction
- **Comprehensive**: Supports 500+ file formats and thousands of metadata tags
- **Forensic Grade**: Extracts metadata that Python libraries may miss
- **HEIC/HEIF Support**: Native support for Apple High-Efficiency formats
- **C2PA/CAI**: Better extraction of Content Authenticity Initiative data

## Installation Instructions

### Windows

1. **Download ExifTool**
   - Visit: https://exiftool.org/
   - Download the **Windows Executable** (exiftool-12.xx.zip or similar)

2. **Extract and Rename**
   - Extract the ZIP file
   - Rename `exiftool(-k).exe` to `exiftool.exe`

3. **Add to PATH** (Option A - Recommended)
   - Move `exiftool.exe` to `C:\Windows\System32\`
   - OR create a folder like `C:\exiftool\` and add it to your system PATH

4. **Verify Installation**
   ```powershell
   exiftool -ver
   ```
   Should display the version number (e.g., `12.70`)

### Linux (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install libimage-exiftool-perl
exiftool -ver
```

### macOS

```bash
brew install exiftool
exiftool -ver
```

## Verification

After installation, run the MetaForensicAI system:

```bash
python forensicai.py --image your_image.jpg
```

You should see:
```
[✓] ExifTool 12.xx detected - using native extraction
```

If ExifTool is not found, you'll see:
```
[!] ExifTool not found - using Python-based extraction (Pillow + exifread)
```

The system will work in both cases, but ExifTool provides superior metadata extraction.

## Troubleshooting

### Windows: "exiftool is not recognized"
- Ensure `exiftool.exe` is in your PATH
- Try placing it in `C:\Windows\System32\`
- Restart your terminal/PowerShell after adding to PATH

### Linux/Mac: Permission denied
```bash
sudo chmod +x /usr/local/bin/exiftool
```

### Still not working?
The system will automatically use Python-based extraction as a fallback. All features will work, though some advanced metadata may not be extracted.
