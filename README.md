# claude-voice-mcp

Talk to **Claude Code on your Mac** while you drive, walk or cook, using the **voice mode of the Claude mobile app**.

The Claude app's voice mode can only use remote connectors (MCP servers reachable by URL). This small server is such a connector: it hands each spoken request to Claude Code running headless on your Mac, which keeps access to everything it normally has (local files, notes, CLIs, MCP servers, skills), and sends back a short answer written to be read aloud.

> "What's left on my to-do list for the client meeting tomorrow?"
> "Note that the plumber comes Thursday at 9."
> "Find the last invoice from Acme in my email and tell me the amount."

## How it works

```
Claude app (voice) ──HTTPS──▶ Cloudflare ──tunnel──▶ this server (127.0.0.1) ──▶ claude -p … ──▶ your tools
        ▲                                                                              │
        └──────────────────────── short answer as the MCP tool result ◀────────────────┘
```

- Requests go through a Cloudflare Tunnel: no port is opened on your Mac or router.
- Each request runs `claude -p` with Sonnet, low effort and `--permission-mode auto`, plus a system prompt that asks for one to four plain sentences.
- Follow-up questions resume the same Claude Code session (`session_id`).
- Requests longer than about 50 seconds return a task id; the voice assistant fetches the result later.

### Tools

| Tool | What it does |
| --- | --- |
| `ask_claude_code` | Hands a request to Claude Code and returns a short spoken-style answer. |
| `get_task_result` | Fetches the result of a request that was still running. |
| `save_note` | Saves a dictated Markdown note instantly (no agent, no model cost). |

## Requirements

- macOS, with the Mac awake and online when you call it.
- [Claude Code](https://code.claude.com) installed and signed in (`claude` in `~/.local/bin`, or set `CLAUDE_BIN`).
- Node.js 20 or later.
- A Claude plan that allows custom connectors in the Claude app.
- A domain on Cloudflare, Cloudflare Zero Trust (the free plan is enough) and `cloudflared`.
- Optional: the [`cf` CLI](https://developers.cloudflare.com/) logged in, used by `scripts/install.sh` to create the DNS record and Access application. You can also create both in the dashboard.

## Setup

1. **Install**
   ```bash
   git clone https://github.com/guillaume-gonano/claude-voice-mcp && cd claude-voice-mcp
   npm install && npm test
   ```
2. **Create the tunnel** in Cloudflare Zero Trust → Networks → Tunnels: a remotely managed tunnel with a public hostname (for example `mcp.example.com`) pointing to `http://127.0.0.1:47851`. Save its token in `data/tunnel-token` (`chmod 600`).
3. **Fill in your settings**
   ```bash
   mkdir -p data
   cp install.env.example data/install.env
   cp config.example.json data/config.json
   ```
   Edit both files (see [Configuration](#configuration)).
4. **Run the installer**
   ```bash
   scripts/install.sh
   ```
   It creates the DNS record if needed and a Cloudflare Access application on `/authorize`, limited to your email. It then writes `data/config.json` and starts two LaunchAgents: the server and the tunnel. It ends with checks: `/mcp` must answer 401 and `/authorize` 302.
5. **Add the connector** in the Claude app: Settings → Connectors → Add custom connector → `https://mcp.example.com/mcp`. Sign in with Cloudflare Access when asked. Then start voice mode and ask something.

## Configuration

`data/config.json` (personal, never committed):

| Key | Meaning |
| --- | --- |
| `userName` | Your first name, used in the prompts. |
| `notesDir` | Folder for `save_note` and long details (for example an Obsidian inbox). |
| `noteFrontmatter` | Extra YAML fields added to every note. |
| `toolsHint` | What Claude Code can reach on your Mac. The voice assistant reads it to decide when to call the tool. |
| `extraPrompt` | Extra instructions appended to the voice system prompt (language, house rules). |

The installer adds `publicUrl`, `port` and `access`.

Environment variables: `CLAUDE_BIN`, `VOICE_MCP_MODEL` (default `sonnet`), `VOICE_MCP_EFFORT` (default `low`) and `VOICE_MCP_WAIT_MS` (default `50000`).

## Security

**Read this before installing:** this connector gives a full Claude Code agent, running with your user account's rights, to whoever can use it.

The connector uses several layers of protection:

- **No inbound port.** The server listens on `127.0.0.1` only, and `cloudflared` makes an outgoing connection.
- **OAuth 2.1 with PKCE.** `/mcp` refuses any request without a valid token (401).
- **Only the Claude apps can register as clients.** Only the claude.ai and claude.com callback URLs are accepted; anything else is refused with 400.
- **Tokens are issued only after your sign-in.** `/authorize` sits behind Cloudflare Access, limited to your email. The server also checks the Access JWT signature, audience and email itself.
- **Tokens are stored as SHA-256 hashes** in `data/oauth-state.json` (mode 0600). Access tokens last 24 hours; refresh tokens last 90 days and rotate on each use.
- **Three narrow tools**, with no direct shell access.
- **Claude Code's own guardrails stay on.** Auto permission mode applies, and the voice prompt forbids sending, publishing, deleting or paying unless you explicitly ask.

Remaining risks you should accept knowingly:

- **Your Claude account is the key.** Anyone signed in to it can use the connector, so protect it with strong sign-in (2FA or passkey).
- **Prompt injection is reduced, not eliminated.** An email or web page that Claude Code reads could contain hostile instructions.
- **"Always allow" removes a human check.** Setting the tools to "Always allow" in the Claude app means no confirmation before each call.

To cut access immediately, disconnect the connector in Claude, or stop the tunnel:
```bash
launchctl bootout gui/$(id -u)/local.claude-voice-mcp-tunnel
```

## Limits

- Each request starts Claude Code, so expect roughly 10 seconds for a simple answer, and more for real work.
- Requests use your Claude Code usage or quota like any other session.
- The Mac must stay awake: for example, use `caffeinate`, or Energy settings that prevent sleep.

## Development

```bash
npm test   # OAuth flow, Access guard, tools and notes, with a fake Claude Code
```

## License

MIT. Not affiliated with Anthropic.
