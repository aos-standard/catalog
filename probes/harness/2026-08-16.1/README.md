# Bundled behavior-probe harness

This directory keeps the `services.behavior_probe` package layout
(not a flat module dump). From this directory, measure one server with:

    python -m services.behavior_probe --only <server-name-or-identifier>

That is the single entry. Census is loaded from the public tree's
`census/` directory (walked from this package and from the current
working directory). Override with `--census-dir`. If the census module
is not found, the command fails with an explicit error. It does not
depend on a repository-internal path.

method_version: `2026-08-16.1`

