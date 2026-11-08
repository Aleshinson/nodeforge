"""Hub summary (hub/check.sh): what a server reports to the hub, read-only."""
import unittest

from test_install import BashCase, put


# check.sh sources nodeforge first, so the stubs go into a wrapper that it sources instead.
STUBBED = r'''
source ./setup
uname() { echo "$RUNNING"; }
uptime() { echo "up 3 days, 2 hours"; }
df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 100 54 46 54%% /\n'; }
free() { printf '               total        used        free      shared  buff/cache   available\nMem:             958         309          83           3         588         649\n'; }
_cve_kernel_state() { if [ "$1" = "${FIXED_REL:-}" ]; then echo fixed; else echo vulnerable; fi; }
_cve_newest_kernel() { echo "${NEWEST:-$RUNNING}"; }
_cve_filter_up() { [ -n "${SHIELD:-}" ]; }
command() { if [ "$1" = -v ] && [ "$2" = docker ]; then [ -n "${NODE:-}" ]; return; fi; builtin command "$@"; }
require_node() { [ -n "${NODE:-}" ] || return 1; NODE_DIR=/opt/remnanode; NODE_SERVICE=remnanode; NODE_CONTAINER=remnanode; }
_compose_service_key() { echo "remnawave/node:latest"; }
docker() { echo "${NODE_STATE:-running}"; }
_node_hub_tags() { echo "3.4.3 2026-10-30 sha256:aa"; }
_node_running_version() { echo "${NODE_VERSION:-}"; }
'''


class SummaryTests(BashCase):
    def summary(self, **env):
        wrapper = self.base / "setup.stub"
        put(wrapper, STUBBED)
        head = "".join(f'export {k}="{v}"; ' for k, v in {"RUNNING": "6.8.0-149-generic", **env}.items())
        result = self.bash(head + 'bash hub/check.sh "$1"', wrapper)
        self.assert_ok(result)
        return dict(line.split("=", 1) for line in result.stdout.splitlines())

    def test_plain_server(self):
        s = self.summary(FIXED_REL="6.8.0-149-generic")
        self.assertEqual(s, {"kernel": "6.8.0-149-generic", "cve98432": "fixed", "uptime": "3 days, 2 hours",
                             "disk": "54%", "mem_free_mb": "649"})

    def test_open_hole_with_the_fix_waiting_for_a_reboot(self):
        s = self.summary(RUNNING="6.8.0-147-generic", FIXED_REL="6.8.0-149-generic", NEWEST="6.8.0-149-generic", SHIELD="1")
        self.assertEqual(s["cve98432"], "vulnerable")
        self.assertEqual(s["cve98432_pending"], "6.8.0-149-generic")
        self.assertEqual(s["cve98432_shield"], "on")

    def test_node_reports_its_state_and_version(self):
        s = self.summary(NODE="1", NODE_VERSION="3.4.3")
        self.assertEqual((s["remnanode"], s["remnanode_version"]), ("running", "3.4.3"))

    def test_every_value_is_one_line(self):
        # The hub splits on the first "=", one pair per line.
        s = self.summary(NODE="1", NODE_STATE="exited")
        self.assertEqual(s["remnanode"], "exited")
        self.assertEqual(s["remnanode_version"], "")


if __name__ == "__main__":
    unittest.main()
