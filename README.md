# Sender / Receiver tenant pilot

Two tenants that hit each other and show, on both screens, **where each hit came from and where it landed**.

- **sender**: you enter the receiver's IP and send hits to it. Dashboard on port `8001`.
- **receiver**: you enter the sender's IP. Every incoming hit is checked against it. Dashboard on port `8002`.

You only need Python 3.8+. There's nothing to install.

## Run

On machine A (sender):

```bash
python3 sender.py                 # or: python3 sender.py --peer 10.0.0.20
```

On machine B (receiver):

```bash
python3 receiver.py               # or: python3 receiver.py --peer 10.0.0.10
```

Open `http://<machine-A-ip>:8001/` and `http://<machine-B-ip>:8002/`, type the other machine's IP on each screen, and press **Save**. Then press **Send hit**.

Options: `--port N` (listen port), `--host IP` (listen interface, default all), `--peer IP[:port]`.
The peer IP you enter is saved in `data/<role>_config.json`. Every hit is also written to `data/<role>_hits.jsonl`.

If the machines can't reach each other, open the ports in the firewall, e.g. `sudo ufw allow 8001/tcp` / `sudo ufw allow 8002/tcp`.

## What you see

**Incoming hits (who hit me)**
| Field | Meaning |
|---|---|
| Origin | Source IP:port of the TCP connection, as the receiving socket saw it. This is the real origin and can't be faked by the caller. |
| Reached | The local IP:port the hit arrived on, plus the `Host` header the caller dialed |
| Caller | Role and hostname, if the caller is a tenant. Otherwise "not a tenant" and its user agent (curl, browser…) |
| Check | ✓ when the origin matches the peer IP you entered. ✗ when it doesn't |
| NAT note | Shown when the IP the caller thinks it has is different from the origin you saw |

**Outgoing hits (who I hit)**
| Field | Meaning |
|---|---|
| Source | The local IP:port the OS actually used to send the hit |
| Destination | Peer IP:port |
| What the other side saw | The origin the peer recorded and where it landed. Flagged **IP rewritten** when it differs from your source (NAT/proxy) |
| Result | Delivered with latency, or the exact error (refused, timeout, no route…) |

## Hitting a tenant from anything else

```bash
curl "http://<tenant-ip>:8002/hit?msg=from-curl"
curl -X POST http://<tenant-ip>:8002/hit -d '{"message":"hi"}'
```

The response tells the caller what origin IP the tenant saw.

> Pilot only: there's no authentication, so anyone who can reach the port can use the dashboard and the API.
# simulation_network
