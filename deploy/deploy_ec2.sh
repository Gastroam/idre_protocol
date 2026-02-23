#!/bin/bash
# ============================================================
# IDRE EC2 Full Deployment Script
# Run as: sudo bash deploy_ec2.sh
# ============================================================
set -euo pipefail

REPO_URL="https://github.com/Gastroam/idre_clean.git"
DEPLOY_DIR="/opt/idre"
DEMO_PEPPER="idre_demo_pepper_2026_ec2"
DEMO_SEED=7245
NODE_A_PORT=8890
NODE_B_PORT=8891
DEMO_API_PORT=5000

echo "============================================================"
echo "  IDRE EC2 Deployment"
echo "============================================================"

# 1. System packages
echo "[1/7] Installing system packages..."
apt update -y
apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx git

# 2. Clone repo  
echo "[2/7] Cloning IDRE repository..."
if [ -d "$DEPLOY_DIR" ]; then
    cd "$DEPLOY_DIR/idre_clean"
    git pull --ff-only || true
else
    mkdir -p "$DEPLOY_DIR"
    cd "$DEPLOY_DIR"
    git clone "$REPO_URL"
fi

cd "$DEPLOY_DIR/idre_clean"

# 3. Python venv + deps
echo "[3/7] Setting up Python environment..."
python3 -m venv /opt/idre/venv
source /opt/idre/venv/bin/activate
pip install --upgrade pip
pip install numpy flask gunicorn

# 4. Generate vocab.jsonl if missing
echo "[4/7] Generating vocab.jsonl..."
if [ ! -f "$DEPLOY_DIR/idre_clean/vocab.jsonl" ]; then
    python3 -c "
import json
tokens = [chr(i) for i in range(32, 127)] + ['<PAD>', '<UNK>', '<BOS>', '<EOS>']
with open('vocab.jsonl', 'w') as f:
    for i, t in enumerate(tokens):
        f.write(json.dumps({'token': t, 'index': i}) + '\n')
print(f'Generated vocab.jsonl with {len(tokens)} tokens')
"
fi

# 5. Install systemd services
echo "[5/7] Installing systemd services..."

# Node A (Alice)
cat > /etc/systemd/system/idre-node-a.service << 'UNIT'
[Unit]
Description=IDRE HIVE Node A (Alice)
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/idre/idre_clean
Environment="PYTHONPATH=/opt/idre"
ExecStart=/opt/idre/venv/bin/python scripts/hive_v12_node_server.py \
    --node-id ALICE \
    --seed 7245 \
    --pepper "idre_demo_pepper_2026_ec2" \
    --port 8890 \
    --backend frozen \
    --freeze-field \
    --rl-challenge-rps 5.0 \
    --rl-challenge-burst 10.0 \
    --rl-verify-rps 2.0 \
    --rl-verify-burst 5.0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# Node B (Bob)
cat > /etc/systemd/system/idre-node-b.service << 'UNIT'
[Unit]
Description=IDRE HIVE Node B (Bob)
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/idre/idre_clean
Environment="PYTHONPATH=/opt/idre"
ExecStart=/opt/idre/venv/bin/python scripts/hive_v12_node_server.py \
    --node-id BOB \
    --seed 7245 \
    --pepper "idre_demo_pepper_2026_ec2" \
    --port 8891 \
    --backend frozen \
    --freeze-field \
    --rl-challenge-rps 5.0 \
    --rl-challenge-burst 10.0 \
    --rl-verify-rps 2.0 \
    --rl-verify-burst 5.0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# Demo API
cat > /etc/systemd/system/idre-demo.service << 'UNIT'
[Unit]
Description=IDRE Demo API
After=idre-node-a.service idre-node-b.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/idre/idre_clean
Environment="PYTHONPATH=/opt/idre:/opt/idre/idre_clean/scripts"
Environment="IDRE_SEED=7245"
Environment="IDRE_PEPPER=idre_demo_pepper_2026_ec2"
ExecStart=/opt/idre/venv/bin/gunicorn \
    --bind 127.0.0.1:5000 \
    --workers 2 \
    --timeout 30 \
    "demo_api:app"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable idre-node-a idre-node-b idre-demo

# 6. nginx config
echo "[6/7] Configuring nginx..."

cat > /etc/nginx/sites-available/idre << 'NGINX'
server {
    listen 80;
    server_name idre.mti-evo.online;

    # Static landing page
    root /var/www/idre;
    index index.html;

    # Gzip
    gzip on;
    gzip_types text/plain text/css application/javascript application/json;
    gzip_min_length 256;

    # Demo API (Flask/Gunicorn)
    location /api/ {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }

    # Node A — raw protocol endpoints for security testing
    location /node-a/ {
        proxy_pass http://127.0.0.1:8890/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Node B — raw protocol endpoints for security testing
    location /node-b/ {
        proxy_pass http://127.0.0.1:8891/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Static files
    location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|webp|woff2)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}
NGINX

ln -sf /etc/nginx/sites-available/idre /etc/nginx/sites-enabled/idre
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

# 7. Create landing page placeholder
echo "[7/7] Creating landing page..."
mkdir -p /var/www/idre
cat > /var/www/idre/index.html << 'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDRE — Live HIVE Node</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', system-ui, sans-serif; background: #0a0a0f; color: #e0e0e0; min-height: 100vh; }
        .container { max-width: 900px; margin: 0 auto; padding: 2rem; }
        h1 { font-size: 2.5rem; background: linear-gradient(135deg, #00f5d4, #7b2ff7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 0.5rem; }
        h2 { color: #7b2ff7; margin: 2rem 0 1rem; font-size: 1.3rem; }
        .subtitle { color: #888; font-size: 1.1rem; margin-bottom: 2rem; }
        .card { background: #12121a; border: 1px solid #222; border-radius: 12px; padding: 1.5rem; margin: 1rem 0; }
        .endpoint { font-family: 'Fira Code', monospace; background: #1a1a2e; padding: 0.8rem 1rem; border-radius: 8px; margin: 0.5rem 0; border-left: 3px solid #00f5d4; font-size: 0.9rem; }
        .method { color: #00f5d4; font-weight: bold; }
        .desc { color: #999; font-size: 0.85rem; margin-top: 0.3rem; }
        a { color: #7b2ff7; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .status { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #00f5d4; margin-right: 8px; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .badge { display: inline-block; background: #1a1a2e; border: 1px solid #333; border-radius: 20px; padding: 0.3rem 0.8rem; font-size: 0.8rem; margin: 0.2rem; }
        code { background: #1a1a2e; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.85rem; }
        .warning { background: #2a1a0a; border-color: #f5a623; color: #f5a623; padding: 1rem; border-radius: 8px; margin: 1rem 0; border: 1px solid; }
    </style>
</head>
<body>
    <div class="container">
        <h1>IDRE Protocol — Live Node</h1>
        <p class="subtitle"><span class="status"></span> HIVE-P2P/1.2 • Two nodes running • Open for testing</p>

        <div class="card">
            <strong>What is this?</strong>
            <p style="margin-top:0.5rem; color:#bbb;">Two IDRE HIVE nodes (Alice & Bob) running the full protocol stack. Security researchers can interact with the protocol, inspect wire format, and test attack vectors.</p>
            <p style="margin-top:0.5rem;">
                <span class="badge">57 tests pass</span>
                <span class="badge">Pepper MANDATORY</span>
                <span class="badge">Rate limited</span>
                <span class="badge">HMAC-SHA256</span>
            </p>
        </div>

        <h2>🔬 Interactive Demo API</h2>
        <div class="endpoint"><span class="method">GET</span> <a href="/api/demo/status">/api/demo/status</a><div class="desc">Health check — see both nodes' state</div></div>
        <div class="endpoint"><span class="method">POST</span> /api/demo/send<div class="desc">Encrypt a message (Alice→Bob). Body: <code>{"message": "hello"}</code>. Returns wire format.</div></div>
        <div class="endpoint"><span class="method">POST</span> /api/demo/receive<div class="desc">Submit wire message to Bob. Try tampering first! Body: <code>{"wire_message": {...}}</code></div></div>
        <div class="endpoint"><span class="method">POST</span> /api/demo/handshake<div class="desc">Walk through a full challenge/verify handshake</div></div>
        <div class="endpoint"><span class="method">GET</span> <a href="/api/demo/fingerprint">/api/demo/fingerprint</a><div class="desc">Public fingerprint bits — what an attacker observes</div></div>
        <div class="endpoint"><span class="method">GET</span> <a href="/api/demo/config">/api/demo/config</a><div class="desc">Public config + attacker's challenge</div></div>

        <h2>🎯 Raw Protocol Endpoints (Attack Surface)</h2>
        <div class="endpoint"><span class="method">GET</span> <a href="/node-a/health">/node-a/health</a><div class="desc">Node A (Alice) — health probe</div></div>
        <div class="endpoint"><span class="method">GET</span> <a href="/node-b/health">/node-b/health</a><div class="desc">Node B (Bob) — health probe</div></div>
        <div class="endpoint"><span class="method">POST</span> /node-a/hive/v12/challenge<div class="desc">Initiate handshake with Node A (rate limited: 5 req/s)</div></div>
        <div class="endpoint"><span class="method">POST</span> /node-a/hive/v12/verify_req/process<div class="desc">Submit encrypted message to Node A (rate limited: 2 req/s)</div></div>

        <div class="warning">⚠️ Rate limiting is active. Burst floods will trigger HTTP 429. This is intentional — test it.</div>

        <h2>📄 Resources</h2>
        <div class="card">
            <p><a href="https://github.com/Gastroam/idre_protocol">GitHub Repository</a> — Full source, tests, attack suite</p>
            <p style="margin-top:0.5rem;"><a href="https://mti-evo.online">MTI-EVO Project</a> — Parent project</p>
        </div>

        <p style="margin-top:3rem; color:#555; font-size:0.8rem; text-align:center;">
            IDRE v2.4 • Integer-Dependent Receiver Encoding • © 2026 Miguel A. Morelo Bustamante
        </p>
    </div>
</body>
</html>
HTML

echo ""
echo "============================================================"
echo "  Deployment complete!"
echo "============================================================"
echo ""
echo "Starting services..."
systemctl start idre-node-a idre-node-b
sleep 2
systemctl start idre-demo

echo ""
echo "Services status:"
systemctl is-active idre-node-a idre-node-b idre-demo || true

echo ""
echo "Next steps:"
echo "  1. Point idre.mti-evo.online DNS to this server's IP"
echo "  2. Run: sudo certbot --nginx -d idre.mti-evo.online"
echo "  3. Test: curl http://localhost:8890/health"
echo "  4. Test: curl http://localhost:5000/api/demo/status"
echo ""
