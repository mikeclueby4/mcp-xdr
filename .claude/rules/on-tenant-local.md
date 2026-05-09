---
paths: [ '**/tenant.local.md', '**/*.local.md' ]
---

`tenant.local.md` (any `*.local.md`) is meant for tenant-specific facts, and is *not* shipped in the public repo.

When writing/updating `tenant.local.md`: 
  - be very concise (LLM-optimized terse!)
  - use good trigger phrases for facts that future-you will need, to know e.g. "safe vs risky" in our logs.
  - `tenant.local.md` gets injected as-is into `xdr` skills and _will_ cost context tokens. 
  
  
Other `.local.md` files are only referenced, not transcluded. Mention them in `tenant.local.md` along with good trigger phrases if you want other `.local.md` files to be considered by LLMs consuming `tenant.local.md`.