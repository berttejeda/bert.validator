# Changelog

All notable changes to `bert.validator` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Optional top-level `title` and `description` manifest fields. Both are purely descriptive, are template-rendered, and are taken from the manifest passed on the command line (included manifests' values are ignored). They are shown:
  - as a banner at the start of a run and under the `--list` heading, and the title again under the final `--- Validation Summary ---` heading;
  - in `--visualize`: the title labels the mindmap root node and the page `<title>`, and a header card shows the title and description (links in the description are clickable);
  - in `--export-as-mop`: the title becomes the document heading and the description a blockquote;
  - in `--log-file` output: `title` / `description` keys in JSON and YAML, a heading and blockquote in Markdown.
- Review toggles in the `--visualize` mindmap: every validation has a clickable chip that reads "Needs Review" (amber) and switches to "Reviewed" (green). Validations that passed start out as "Reviewed"; everything else starts as "Needs Review". Choices are kept while folding and unfolding branches but are not persisted between page loads. Light and dark themes are supported.
- `CHANGELOG.md`.

### Changed
- The `--visualize` header card no longer ignores mouse events, so long descriptions can be scrolled and links clicked.
- README flag table now documents `--output`, `--log-file` and `--log-file-format`; the code walkthrough now covers `visualize.go`, `mop.go` and the title/description plumbing.

## [1.8.1] - 2026-09-21

### Fixed
- Branch and pie chart colors in the `--visualize` output now match consistently for each outcome (PASS green, FAIL red, WARN yellow, SKIP blue).

## [1.8.0] - 2026-09-18

### Added
- `--export-as-mop[=path.md]`: convert the finalized manifest (includes resolved, loops unrolled, templates rendered) into a Markdown Method of Procedure, so the validations can be run by hand where `validator` isn't available.

## [1.7.1] - 2026-09-17

### Added
- `--visualize[=path.html]`: render the validation summary as an interactive, self-contained HTML mindmap with a Mermaid pie chart overview and collapsible per-validation output.

### Fixed
- Markdown link formatting in notes and validation names.

## [1.6.0] - 2026-08-12

### Added
- Detection of Python virtual environments, including those created by `uv`.

## [1.5.0] - 2026-08-11

### Added
- `--log-file` / `--log-file-format`: save captured output and results to a JSON, YAML or Markdown file.

## [1.4.0] - 2026-08-11

### Added
- Per-manifest `init` blocks for setup and prerequisite checks, with optional `skip_error`.

## [1.3.0] - 2026-08-11

### Added
- Markdown-formatted web links (`[text](url)`) in names and notes, rendered as clickable terminal hyperlinks where supported.

## [1.2.0] - 2026-08-10

### Added
- Release workflow and Homebrew formula.
- LICENSE file.

[Unreleased]: https://github.com/berttejeda/bert.validator/compare/v1.8.1...HEAD
[1.8.1]: https://github.com/berttejeda/bert.validator/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/berttejeda/bert.validator/compare/v1.7.1...v1.8.0
[1.7.1]: https://github.com/berttejeda/bert.validator/compare/v1.6.0...v1.7.1
[1.6.0]: https://github.com/berttejeda/bert.validator/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/berttejeda/bert.validator/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/berttejeda/bert.validator/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/berttejeda/bert.validator/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/berttejeda/bert.validator/releases/tag/v1.2.0
