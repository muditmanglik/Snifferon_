# Snifferon Development Patterns

> Auto-generated skill from repository analysis

## Overview

Snifferon is a Python-based project that follows a flexible development approach with mixed coding styles and freeform commit patterns. The codebase emphasizes simplicity and adaptability, utilizing camelCase file naming conventions and maintaining a lean structure without heavy framework dependencies.

## Coding Conventions

### File Naming
- **Pattern:** camelCase
- **Examples:**
  ```
  networkSniffer.py
  packetAnalyzer.py
  configManager.py
  ```

### Import Style
- **Approach:** Mixed imports based on context
- **Examples:**
  ```python
  # Standard library imports
  import os
  import sys
  from collections import defaultdict
  
  # Third-party imports
  import requests
  from scapy.all import *
  
  # Local imports
  from . import utils
  import networkSniffer
  ```

### Export Style
- **Pattern:** Mixed export patterns
- Functions and classes exported as needed
- No strict module export conventions

### Commit Messages
- **Style:** Freeform with occasional prefixes
- **Average length:** 33 characters
- **Common prefixes:** `chore:`
- **Examples:**
  ```
  chore: cleanup duplicate styles
  fix packet parsing issue
  add new filter options
  ```

## Workflows

### Style Cleanup Workflow
**Trigger:** When duplicate CSS files are detected in the repository
**Command:** `/cleanup-styles`

1. **Identify redundant stylesheet**
   - Scan project for duplicate CSS files
   - Compare `style.css` and `static/style.css`
   - Determine which version contains the most current styles

2. **Remove duplicate file**
   - Delete the redundant stylesheet
   - Update any references in HTML templates
   - Verify no broken styling links remain

3. **Create pull request for cleanup**
   - Commit changes with descriptive message
   - Push to feature branch
   - Open PR with cleanup details

4. **Merge cleanup changes**
   - Review styling consistency
   - Test UI components
   - Merge to main branch

**Files typically involved:**
- `style.css`
- `static/style.css`
- HTML template files

## Testing Patterns

### Test File Structure
- **Pattern:** `*.test.*` naming convention
- **Examples:**
  ```
  networkSniffer.test.py
  packetAnalyzer.test.py
  utils.test.py
  ```

### Testing Approach
- Framework-agnostic testing structure
- Flexible test organization
- Focus on core functionality validation

## Commands

| Command | Purpose |
|---------|---------|
| `/cleanup-styles` | Remove duplicate stylesheet files and update references |
| `/format-code` | Apply camelCase naming and mixed import conventions |
| `/run-tests` | Execute test suite using detected test pattern |
| `/commit-style` | Create freeform commit message following project patterns |