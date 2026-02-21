# Contributing to SOC Query Library

Thank you for your interest in contributing! This library thrives on community expertise.

## How to Contribute

1. **Fork** the repository
2. **Create a branch** (`git checkout -b feature/new-detection`)
3. **Add your query** following the template below
4. **Test** your query in a lab environment
5. **Submit a Pull Request** with a clear description

## Query Template

Every query file must include:

```
// ============================================================
// Title: [Detection Name]
// Description: [What this detects]
// MITRE ATT&CK: [Technique IDs]
// Severity: [Low | Medium | High | Critical]
// Data Sources: [Required log sources]
// Author: [Your Name]
// Date: [YYYY-MM-DD]
// ============================================================
```

### Requirements
- **Tested** in a lab or production environment
- **Documented** with inline comments explaining logic
- **Tuning section** with recommendations for reducing noise
- **False positive notes** describing known benign triggers
- **MITRE ATT&CK mapping** with valid technique IDs

## Code of Conduct

- Be respectful and constructive
- Focus on detection quality over quantity
- Share knowledge openly

## Questions?

Open an issue and we'll respond promptly.
