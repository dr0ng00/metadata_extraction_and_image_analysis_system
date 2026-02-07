# Exports Directory

Contains exported forensic data for integration with other systems.

## Export Formats

### 📊 CSV (`csv/`)
- Tabular data for spreadsheets
- Easy import into databases
- Simple text format

### 📋 XML (`xml/`)
- Structured data for systems
- Defined schema validation
- System integration ready

## Generating Exports

```bash
# Export to CSV
python scripts/export_to_csv.py --input analysis.json --output exports/csv/

# Export to XML
python scripts/export_to_xml.py --input analysis.json --output exports/xml/

# Batch export
python scripts/batch_export.py --format both --output exports/