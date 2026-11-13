# Dokploy MCP

A small, self-hosted [Model Context Protocol](https://modelcontextprotocol.io) server for [Dokploy](https://dokploy.com), written in Rust. It exposes 100 tools for projects, environments, applications, compose stacks, deployments and domains, and protects them with a password-based OAuth 2.1 login (PKCE + dynamic client registration).

Works with Claude Code, claude.ai (including the mobile apps) and ChatGPT.

Schlanker Dokploy-MCP-Server in Rust mit passwortgeschütztem OAuth und 100 Werkzeugen für Projekte, Anwendungen und Deployments.

## Features

- Tool catalog derived from the official `@dokploy/mcp` 0.30.7, checked and updated against the Dokploy **v0.31.2** API.
- Secrets in Dokploy responses (env, build args, passwords, tokens, keys) are replaced with `[REDACTED]`.
- Single-password login page with lockout after repeated failures, rate limits, strict Host/Origin checks and security headers.
- Access tokens last 1 hour; refresh tokens last 90 days after their last use, so active clients stay signed in.
- OAuth state lives in one SQLite file (`/data/oauth.sqlite`).

## Deploy on Dokploy

1. Create an **Application** with build type **Dockerfile** from this repository.
2. Set the environment variables (see `.env.example`):

   | Variable | Meaning |
   |---|---|
   | `BASE_URL` | Public HTTPS origin of this server, e.g. `https://dokploy-mcp.example.com` |
   | `DOKPLOY_URL` | HTTPS origin of your Dokploy panel |
   | `DOKPLOY_API_KEY` | A Dokploy API key (create one without rate limiting) |
   | `MCP_LOGIN_PASSWORD` | Login password, at least 32 bytes |
   | `DATABASE_PATH` | Defaults to `/data/oauth.sqlite` |
   | `PORT` | Defaults to `8787` |

3. Mount a persistent volume at `/data`.
4. Add a domain pointing to port `8787` with HTTPS.

The MCP endpoint is served at both `/` and `/mcp`.

## Connect

- **Claude Code:** `claude mcp add --transport http dokploy https://dokploy-mcp.example.com/mcp`, then `/mcp` → dokploy → Authenticate.
- **claude.ai / Claude mobile:** Settings → Connectors → Add custom connector → `https://dokploy-mcp.example.com/mcp`.
- **ChatGPT:** add it as a connector with the same URL.

Each client opens the login page once; enter `MCP_LOGIN_PASSWORD` and approve.

## Development

```bash
cargo test
```

## License

Apache-2.0. Tool definitions are derived from [Dokploy/mcp](https://github.com/Dokploy/mcp); see `NOTICE` and `LICENSE.dokploy`.
