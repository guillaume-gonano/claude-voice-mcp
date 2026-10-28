# claude-voice-mcp

Remote MCP server (`server.mjs`) that lets the Claude app's voice mode hand requests to Claude Code on this Mac.

- Tools: `ask_claude_code` (runs `claude -p`, Sonnet, low effort, auto mode, short spoken answer, resumes with `session_id`), `get_task_result` (tasks longer than 25 s; the Claude app drops a tool call after ~40 s).
- Security: built-in OAuth (only claude.ai / claude.com redirect URIs may register, tokens stored as hashes); `/authorize` behind Cloudflare Access (JWT verified by the server) or, with any other tunnel, a password (`password` in config, 16+ chars, lock after 5 failures).
- Never committed: `data/` (config.json, install.env, tunnel-token, oauth-state.json, all 0600) and `run/` (logs). Never print the tunnel token.
- Personal settings live only in `data/config.json` and `data/install.env`; keep the code generic (examples: `config.example.json`, `install.env.example`).
- Install / repair: `scripts/install.sh`. Tests: `npm test`.
