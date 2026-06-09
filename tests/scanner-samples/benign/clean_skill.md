# Text Formatter Skill

A simple text formatting skill for OpenCode.

## Trigger
/format

## Description

This skill formats code with consistent indentation and removes
trailing whitespace. It supports Python, JavaScript, and TypeScript.

## Usage

```
/format --indent 4 --style pep8
```

## Parameters

- `indent`: Number of spaces per level (default: 4)
- `style`: Formatting style to apply (pep8, prettier, standard)
- `language`: Target language (auto-detected if omitted)

## Examples

Format a Python file:
```
/format src/main.py --style pep8
```

Format with custom indent:
```
/format src/app.ts --indent 2 --style prettier
```
