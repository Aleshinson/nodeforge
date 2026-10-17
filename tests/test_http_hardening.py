"""Exercise the real config migration and transaction; stub Docker/network only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
CONFIG = '''map $http_upgrade $connection_upgrade { default upgrade; "" close; }
ssl_protocols TLSv1.3;
server {
    server_name de.example.org;
    listen unix:/dev/shm/nginx.sock ssl proxy_protocol;
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    root /var/www/html;
    index index.html;
    add_header X-Robots-Tag "noindex" always;
    location /api/ {
        add_header Cache-Control "no-store";
        proxy_pass http://unix:/dev/shm/xhttp.socket;
    }
}
server {
    listen unix:/dev/shm/nginx.sock ssl proxy_protocol default_server;
    server_name _;
    ssl_reject_handshake on;
    return 444;
}
'''


class HttpHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=REPO)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.conf = self.base / "nginx.conf"
        self.conf.write_text(CONFIG, encoding="utf-8")
        self.inspect = self.base / "inspect.json"
        self.info = [{"HostConfig": {"NetworkMode": "host"}, "Mounts": [
            {"Type": "bind", "Source": str(self.conf),
             "Destination": "/etc/nginx/conf.d/default.conf"}]}]
        self.save_inspect()
        self.candidate = self.base / "candidate.conf"

    def save_inspect(self):
        self.inspect.write_text(json.dumps(self.info), encoding="utf-8")

    def bash(self, script, *args):
        shim = 'python3() { python "$@" | tr -d "\\r"; }; flock() { :; };' if os.name == "nt" else ""
        return subprocess.run(
            [shutil.which("bash"), "-c", shim + 'source ./setup; ' + script, "test",
             *(str(a) if not isinstance(a, Path) else a.relative_to(REPO).as_posix() for a in args)],
            cwd=REPO, capture_output=True, encoding="utf-8", errors="replace", timeout=30,
        )

    def prepare(self):
        return self.bash('_node_http_tool prepare "$1" "$2"', self.inspect, self.candidate)

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_installer_config_gets_redirect_hsts_and_both_tls_versions(self):
        self.assert_ok(self.prepare())
        conf = self.candidate.read_text()
        self.assertIn('return 301 https://de.example.org$request_uri;', conf)
        self.assertIn('listen 80;', conf)
        self.assertNotIn('ssl_protocols TLSv1.3;', conf)
        self.assertIn('ssl_protocols TLSv1.2 TLSv1.3;', conf)
        # A location with its own add_header does not inherit the server header.
        self.assertEqual(conf.count('add_header Strict-Transport-Security "max-age=31536000" always;'), 2)
        self.assertIn('listen unix:/dev/shm/nginx.sock ssl proxy_protocol;', conf)
        self.assertIn('proxy_pass http://unix:/dev/shm/xhttp.socket;', conf)
        self.assertIn('ssl_reject_handshake on;', conf)
        self.assertEqual(self.conf.read_text(), CONFIG)

    def test_second_run_is_identical(self):
        self.assert_ok(self.prepare())
        once = self.candidate.read_text()
        self.conf.write_text(once)
        self.assert_ok(self.prepare())
        self.assertEqual(self.candidate.read_text(), once)

    def test_full_nginx_config_and_quoted_braces(self):
        self.conf.write_text('events {}\nhttp {\n' + CONFIG.replace(
            'index index.html;', 'index index.html;\n    # ignore { broken syntax\n'
            '    location ~ "^/v[0-9]{1,2}/" { add_header X-Test "a;{b}"; }') + '}\n')
        self.assert_ok(self.prepare())
        conf = self.candidate.read_text()
        self.assertIn('X-Test "a;{b}";', conf)
        self.assertTrue(conf.rstrip().endswith('}'))
        self.assertEqual(conf.count('listen 80;'), 1)

    def test_existing_http_redirect_keeps_acme_challenge(self):
        acme = 'location /.well-known/acme-challenge/ { root /var/www/acme; }'
        self.conf.write_text(CONFIG + '\nserver { listen 80; server_name de.example.org;\n'
                             + acme + '\nlocation / { return 302 https://$host$request_uri; }\n}\n')
        self.assert_ok(self.prepare())
        conf = self.candidate.read_text()
        self.assertEqual(conf.count('listen 80;'), 1)
        self.assertIn(acme, conf)
        self.assertNotIn('return 302', conf)
        self.assertIn('return 301 https://de.example.org$request_uri;', conf)

    def test_existing_hsts_is_updated_without_duplicate(self):
        self.conf.write_text(CONFIG.replace('index index.html;',
            'index index.html; add_header Strict-Transport-Security "max-age=0";'))
        self.assert_ok(self.prepare())
        conf = self.candidate.read_text()
        self.assertNotIn('max-age=0', conf)
        self.assertEqual(conf.count('Strict-Transport-Security'), 2)

    def test_ambiguous_or_unsupported_config_is_rejected_without_write(self):
        for config in [CONFIG.replace('de.example.org', '*.example.org'),
                       CONFIG.replace('index index.html;', 'index index.html; include custom.conf;'),
                       CONFIG + 'server { listen 80; server_name de.example.org other.example.org; }',
                       CONFIG + 'server { listen 443 ssl; server_name other.example.org; }']:
            with self.subTest(config=config):
                self.conf.write_text(config)
                result = self.prepare()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.conf.read_text(), config)

    def test_bridge_network_is_rejected_before_config_change(self):
        self.info[0]['HostConfig']['NetworkMode'] = 'bridge'
        self.save_inspect()
        self.assertNotEqual(self.prepare().returncode, 0)
        self.assertEqual(self.conf.read_text(), CONFIG)

    def test_localhost_only_http_listener_is_not_reported_as_public(self):
        self.conf.write_text(CONFIG + '\nserver { listen 127.0.0.1:80; server_name de.example.org; }')
        result = self.prepare()
        self.assertNotEqual(result.returncode, 0)

    def test_adding_hsts_keeps_inherited_http_headers(self):
        config = CONFIG.replace('    add_header X-Robots-Tag "noindex" always;\n', '')
        self.conf.write_text('add_header X-Frame-Options DENY always;\n' + config)
        self.assert_ok(self.prepare())
        # Adding the first server-level header must copy its formerly inherited headers.
        self.assertEqual(self.candidate.read_text().count('add_header X-Frame-Options DENY always;'), 2)

    def transaction(self, nginx_rc=0, reload_rc=0, probe_rc=0, firewall_rc=0):
        return self.bash('''
INSPECT="$1" BACKUPS="$2" NGINX_RC="$3" RELOAD_RC="$4" PROBE_RC="$5" FIREWALL_RC="$6"
require_node() { NODE_DIR=/opt/remnanode; }
docker() {
  case "$1 $2" in
    'ps --filter') echo 'nginx-id nginx:1.30';;
    'inspect nginx-id') cat "$INSPECT";;
    'exec nginx-id')
      echo "DOCKER:$*" >&2
      [ "$4" != -t ] || return "$NGINX_RC"
      [ "$4" != -s ] || return "$RELOAD_RC";;
    *) echo "UNEXPECTED_DOCKER:$*" >&2; return 99;;
  esac
}
_node_http_probe() { echo PROBE >&2; return "$PROBE_RC"; }
_node_http_open_port() { echo FIREWALL >&2; return "$FIREWALL_RC"; }
set -e
block_http_hardening "$BACKUPS"
''', self.inspect, self.base / 'backups', nginx_rc, reload_rc, probe_rc, firewall_rc)

    def test_transaction_preserves_inode_and_backs_up_before_reload(self):
        inode = self.conf.stat().st_ino
        self.assert_ok(self.transaction())
        self.assertEqual(self.conf.stat().st_ino, inode)
        self.assertIn('listen 80;', self.conf.read_text())
        backups = list((self.base / 'backups').glob('http-*/nginx.conf'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), CONFIG)

    def test_failed_validation_reload_or_probe_restores_original(self):
        for kwargs in [dict(nginx_rc=1), dict(reload_rc=1), dict(probe_rc=1)]:
            with self.subTest(kwargs=kwargs):
                result = self.transaction(**kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.conf.read_text(), CONFIG)
                self.assertNotIn('FIREWALL', result.stderr)

    def test_firewall_failure_is_not_reported_as_success(self):
        result = self.transaction(firewall_rc=1)
        self.assertNotEqual(result.returncode, 0)

    def test_probe_checks_real_status_headers_and_exact_tls_versions(self):
        headers = self.base / 'headers.txt'
        script = '''
HEADERS="$1" CURL_RC="$2"
curl() {
  echo "CURL:$*" >&2
  local output url
  while [ "$#" -gt 0 ]; do
    case "$1" in -D) output="$2"; shift;; http://*|https://*) url="$1";; esac
    shift
  done
  if [[ "$url" = http://* ]]; then
    printf 'HTTP/1.1 301 Moved Permanently\\r\\nLocation: https://de.example.org/\\r\\n' > "$output"
  else
    cp "$HEADERS" "$output"
  fi
  return "$CURL_RC"
}
_node_http_probe de.example.org
'''
        headers.write_text('HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=31536000\n')
        result = self.bash(script, headers, 0)
        self.assert_ok(result)
        self.assertIn('--tlsv1.2 --tls-max 1.2', result.stderr)
        self.assertIn('--tlsv1.3 --tls-max 1.3', result.stderr)
        self.assertIn('--resolve de.example.org:443:127.0.0.1', result.stderr)
        for response, rc in [('HTTP/1.1 200 OK\n', 0),
                             ('HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=0\n', 0),
                             ('HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=31536000\n', 60)]:
            headers.write_text(response)
            self.assertNotEqual(self.bash(script, headers, rc).returncode, 0)

    def test_temporary_redirect_is_not_accepted(self):
        headers = self.base / 'headers.txt'
        for code in ('200', '302', '308'):
            headers.write_text(f'HTTP/1.1 {code} Response\nLocation: https://de.example.org/\n')
            result = self.bash('_node_http_tool headers "$1" http de.example.org', headers)
            self.assertNotEqual(result.returncode, 0)

    def test_apply_firewall_propagates_installer_failure(self):
        result = self.bash('''
fw_load() { SSH_PORT=22; NODE_PORT=2222; TCP_PORTS=443; UDP_PORTS=443; }
fw_neutralize_ufw() { :; }
curl() {
  while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then printf '#!/bin/bash\\nexit 7\\n' > "$2"; return 0; fi
    shift
  done
}
panel_only_apply() { echo PANEL_APPLIED; }
fw_confirm_safety() { echo FALSE_SUCCESS; }
apply_firewall
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('FALSE_SUCCESS', result.stdout)

    def test_panel_filter_failure_cannot_reach_safety_confirmation(self):
        for failure in ('runtime', 'enable', 'restart'):
            result = self.bash('''
FAILURE="$1"
fw_load() { SSH_PORT=22; NODE_PORT=2222; TCP_PORTS=443; UDP_PORTS=443; PANEL_IPS=100.109.8.19; }
fw_neutralize_ufw() { :; }
curl() {
  while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then printf '#!/bin/bash\\nexit 0\\n' > "$2"; return 0; fi
    shift
  done
}
_panel_only_write_runtime() { [ "$FAILURE" != runtime ]; }
systemctl() { [ "$1" != "$FAILURE" ]; }
_panel_in_na_whitelist() { return 0; }
fw_confirm_safety() { echo FALSE_SUCCESS; }
apply_firewall
''', failure)
            self.assertNotEqual(result.returncode, 0, failure)
            self.assertNotIn('FALSE_SUCCESS', result.stdout)

    def test_missing_firewall_or_armed_safety_is_an_error(self):
        for failure in ('table', 'boot', 'safety'):
            result = self.bash('''
FAILURE="$1"
nft() { [ "$FAILURE" != table ]; }
systemctl() { [ "$FAILURE" != boot ]; }
na_safety_armed() { [ "$FAILURE" = safety ]; }
fw_verify
''', failure)
            self.assertNotEqual(result.returncode, 0, failure)

    def test_port_registration_preserves_existing_ports_and_panel_access(self):
        registry = self.base / 'firewall.env'
        registry.write_text('EXTRA_TCP="8443"\nPANEL_IPS="100.109.8.19"\nNODE_PORT="2222"\n')
        result = self.bash('''
FW_ENV="$1"
fw_init() { :; }
nft() { [ "$*" = 'list table inet na_filter' ]; }
ufw() { echo 'Status: inactive'; }
apply_firewall() { fw_load; printf 'PORTS:%s NODE:%s PANEL:%s' "$EXTRA_TCP" "$NODE_PORT" "$PANEL_IPS"; }
_node_http_open_port
''', registry)
        self.assert_ok(result)
        self.assertIn('PORTS:80,8443 NODE:2222 PANEL:100.109.8.19', result.stdout)

    def test_menu_dispatches_http_hardening(self):
        result = self.bash('''
print_menu() { :; }
block_http_hardening() { echo HTTP_HARDENING; }
menu <<< $'j\\n\\n0'
''')
        self.assert_ok(result)
        self.assertIn('HTTP_HARDENING', result.stdout)


if __name__ == '__main__':
    unittest.main()
