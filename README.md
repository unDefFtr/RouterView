# RouterView — RouterOS Network Dashboard

Real-time MikroTik RouterOS monitoring dashboard built with **Rust** (backend) and
**Vue 3 + ECharts** (frontend).

## Architecture

```
RouterOS REST API ──▶ Rust Backend (Axum) ──▶ WebSocket ──▶ Vue 3 Frontend
                         │                                      │
                    Poll Engine                           Pinia Stores
                    (1-5s interval)                       ECharts Charts
```

## Quick Start

### 1. Backend

```bash
cd backend
cp .env.example .env
# Edit .env with your RouterOS credentials
cargo run
```

Server starts on `http://localhost:3001`.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Dev server starts on `http://localhost:5173` with API/WS proxy to backend.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `ROUTEROS_HOST` | `192.168.88.1` | RouterOS IP/hostname |
| `ROUTEROS_PORT` | `80` (HTTP) / `443` (HTTPS) | REST API port |
| `ROUTEROS_SCHEME` | `https` | `http` or `https` |
| `ROUTEROS_USERNAME` | `admin` | Login username |
| `ROUTEROS_PASSWORD` | — | Login password (required) |
| `ROUTEROS_INSECURE_TLS` | `false` | Accept self-signed certs (HTTPS only) |
| `POLL_INTERVAL_SECS` | `3` | Data poll interval |
| `PROBE_INTERVAL_SECS` | `60` | Latency probe interval |
| `SERVER_PORT` | `3001` | Backend listen port |

## Dashboard Layout

- **Top Navbar**: Brand, quick links, LIVE indicator, theme toggle
- **Left Sidebar** (60px): Vertical icon navigation with active highlight
- **Left Column** (30%): System & Gateway Status + ISP Network Probe
- **Right Column** (70%): Traffic Chart → ISP Stability Bar → AP Loss & WiFi Devices

## Tech Stack

- **Backend**: Rust, Axum 0.8, Tokio, reqwest
- **Frontend**: Vue 3, TypeScript, Pinia, ECharts 5, Vite 6
- **Real-time**: WebSocket (tokio broadcast channel)
- **Theming**: CSS Variables (dark/light mode)
