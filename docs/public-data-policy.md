# Public data policy

This repository contains reusable code and synthetic tests. Keep private audit evidence outside the repository.

- Do not commit provider logs, reports, screenshots, packet captures, or credentials.
- Do not name a provider, deployment, cluster, or operator when describing an audit result.
- Do not copy hostnames, addresses, serial numbers, GUIDs, or timestamps from private evidence.
- Build small test cases from the parser or rule contract. Use invented identifiers and label new evidence fixtures synthetic.
- Public API names, driver names, and documented resource keys may remain when code needs them. Do not attach deployment details or measured results.
- Cached public security advisories require a public URL and must stay separate from provider evidence.

Run `python tools/check_public_data.py` before pushing. The check catches known prohibited patterns and artifact paths. It does not replace a provenance review.

Deleting content in a follow-up commit does not remove earlier public revisions. Treat history cleanup as a separate task.
