# Correction, 2026-11-23 (the record above is left as published)

`proposed/proposed_http_vectors.json`, `proposed-url-non-canonical-ipv6-literal`, is wrong. It was signed over
`"@authority": 2001:db8:0:0::1` without brackets, because `reader/agent_did_http_v2.py` builds `@authority` from the
parsed host name and drops the brackets of an IPv6 literal. RFC 9421 §2.2.3 takes the authority of RFC 9110, brackets
included, as the fixture's own vectors do. The fixture's `reject-url-non-canonical-ipv6-literal` (agent-did #306,
`d09ca9f`) signs `[2001:db8:0:0::1]`, which is the right form. The other four `-literal` proposals match #306's
`@authority`, `@path` and `@query` lines exactly.

`check_proposed.py` reported 7/7 because the reader that built the vector and the reader that checked it share the
defect. `../rerun-pr306-d09ca9f/` shows the defect, and its proposed `accept-ipv6-host` vector is the one that catches it.
