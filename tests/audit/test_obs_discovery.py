"""Unit tests for observability-backend auto-discovery.

Every vantage is injected, so these tests exercise the real decision path that
`cmax audit security` takes on a cluster: which endpoints become check targets,
which platforms get reported, and which evidence is deliberately not checked.
"""

from __future__ import annotations

import unittest

from cmax import obs_discovery

SS_OUTPUT = """State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      4096   0.0.0.0:9090        0.0.0.0:*
LISTEN 0      4096   127.0.0.1:3000      0.0.0.0:*
LISTEN 0      4096   [::]:9400           [::]:*
LISTEN 0      4096   *:9100              *:*
LISTEN 0      4096   0.0.0.0:22          0.0.0.0:*
"""


class SocketDiscoveryTests(unittest.TestCase):
    def test_unbracketed_ipv6_listener_preserves_complete_host(self) -> None:
        cases = {
            "::1:9090": "http://[::1]:9090",
            "2001:db8::1:9090": "http://[2001:db8::1]:9090",
            "::ffff:127.0.0.1:9090": "http://[::ffff:127.0.0.1]:9090",
            "fe80::1%eth0:9090": "http://[fe80::1%25eth0]:9090",
            "[::1]:9090": "http://[::1]:9090",
        }
        for address, expected in cases.items():
            with self.subTest(address=address):
                endpoints = obs_discovery.endpoints_from_sockets(
                    f"tcp6 0 0 {address} :::* LISTEN"
                )
                self.assertEqual([e.url for e in endpoints], [expected])
    def test_query_ports_become_targets_and_wildcards_become_localhost(self) -> None:
        endpoints = obs_discovery.endpoints_from_sockets(SS_OUTPUT)
        urls = [endpoint.url for endpoint in endpoints]
        self.assertIn("http://127.0.0.1:9090", urls)
        self.assertIn("http://127.0.0.1:3000", urls)
        self.assertEqual(
            {endpoint.platform for endpoint in endpoints}, {"prometheus", "grafana"}
        )

    def test_exporter_and_unrelated_ports_are_never_checked(self) -> None:
        # An exporter serves its own host's metrics, so checking it cannot answer
        # a tenancy question; port 22 is not a monitoring backend at all.
        urls = [e.url for e in obs_discovery.endpoints_from_sockets(SS_OUTPUT)]
        for port in (":9400", ":9100", ":22"):
            self.assertFalse([url for url in urls if url.endswith(port)], port)

    def test_exporter_ports_still_report_the_platform(self) -> None:
        platforms = obs_discovery.platforms_from_sockets(SS_OUTPUT)
        self.assertIn("dcgm-exporter", platforms)
        self.assertIn("node-exporter", platforms)

    def test_bare_address_lines_parse(self) -> None:
        # The audit collectors record the pre-extracted address column.
        endpoints = obs_discovery.endpoints_from_sockets("0.0.0.0:8428\n[::1]:10902\n")
        self.assertEqual(
            [e.url for e in endpoints],
            ["http://127.0.0.1:8428", "http://[::1]:10902"],
        )

    def test_the_netstat_ipv6_wildcard_form_is_parsed(self) -> None:
        # `ss` prints `[::]:9090`, but `netstat -tln` prints `:::9090`. A host
        # without `ss` falls back to netstat, so an IPv6-only backend was
        # invisible to the socket vantage there.
        netstat = (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp6       0      0 :::9090                 :::*                    LISTEN\n"
            "tcp6       0      0 :::3000                 :::*                    LISTEN\n"
        )
        self.assertEqual(
            [e.url for e in obs_discovery.endpoints_from_sockets(netstat)],
            ["http://127.0.0.1:9090", "http://127.0.0.1:3000"],
        )

    def test_both_ipv6_wildcard_spellings_agree(self) -> None:
        self.assertEqual(
            obs_discovery.parse_listening(":::9090"),
            obs_discovery.parse_listening("[::]:9090"),
        )

    def test_peer_column_wildcard_is_not_a_port(self) -> None:
        pairs = obs_discovery.parse_listening("LISTEN 0 128 10.0.0.5:9090 0.0.0.0:*")
        self.assertEqual(pairs, [("10.0.0.5", 9090)])


class ProcessDiscoveryTests(unittest.TestCase):
    def test_process_names_identify_platforms(self) -> None:
        text = "systemd\nprometheus\ngrafana-server\nvictoria-metrics-prod\nsshd\n"
        self.assertEqual(
            obs_discovery.platforms_from_processes(text),
            ["prometheus", "grafana", "victoriametrics"],
        )

    def test_process_only_backend_gets_a_default_port_target(self) -> None:
        # A containerized Grafana has no systemd unit and may hide its socket
        # from an unprivileged `ss`; the comm name is the only signal left.
        endpoints = obs_discovery.endpoints_from_processes("grafana\n")
        self.assertEqual([e.url for e in endpoints], ["http://127.0.0.1:3000"])

    def test_truncated_exporter_name_is_not_read_as_a_server(self) -> None:
        # `ps -eo comm=` truncates to 15 characters, so
        # `prometheus-node-exporter` arrives as `prometheus-node`. Reading that
        # as Prometheus invents a query target on an exporter-only node.
        self.assertEqual(obs_discovery.platforms_from_processes("prometheus-node\n"), [])
        self.assertEqual(obs_discovery.endpoints_from_processes("prometheus-node\n"), [])
        for comm in ("grafana-agent", "prometheus-adapter", "vmagent"):
            self.assertEqual(
                obs_discovery.platforms_from_processes(f"{comm}\n"), [], comm
            )

    def test_build_suffixed_binaries_are_still_matched(self) -> None:
        self.assertEqual(
            obs_discovery.platforms_from_processes("vmselect-prod\n"), ["vmselect"]
        )
        self.assertEqual(
            obs_discovery.platforms_from_processes("prometheus-3.1.0\n"), ["prometheus"]
        )

    def test_truncated_comm_of_a_long_binary_name_is_matched(self) -> None:
        # `ps -eo comm=` reports the kernel comm, capped at 15 characters, so
        # victoria-metrics-prod arrives as victoria-metric. That is the only form
        # a real host produces, and the 16-character key cannot match it directly.
        self.assertEqual(len("victoria-metric"), obs_discovery.COMM_MAX_LEN)
        self.assertEqual(
            obs_discovery.platforms_from_processes("victoria-metric\n"),
            ["victoriametrics"],
        )
        self.assertEqual(
            [e.url for e in obs_discovery.endpoints_from_processes("victoria-metric\n")],
            ["http://127.0.0.1:8428"],
        )

    def test_a_15_character_comm_does_not_absorb_a_short_key(self) -> None:
        # `prometheus-node` is exactly 15 characters, so it reaches the truncation
        # branch. Only a key of 15 or more characters may be a truncation, so the
        # 10-character `prometheus` key must not claim it.
        self.assertEqual(len("prometheus-node"), obs_discovery.COMM_MAX_LEN)
        self.assertEqual(obs_discovery.platforms_from_processes("prometheus-node\n"), [])


class AuditEvidenceTests(unittest.TestCase):
    def test_recorded_endpoints_become_targets(self) -> None:
        values = {
            "audit_data": {
                "healthChecks": {
                    "monitoringStack": {
                        "prometheus": True,
                        "grafana": False,
                        "endpoints": ["127.0.0.1:9090", "0.0.0.0:3000"],
                        "platforms": ["prometheus", "grafana", "dcgm-exporter"],
                    }
                }
            }
        }
        endpoints, platforms = obs_discovery.endpoints_from_audit(values)
        self.assertEqual(
            sorted(e.url for e in endpoints),
            ["http://127.0.0.1:3000", "http://127.0.0.1:9090"],
        )
        self.assertIn("dcgm-exporter", platforms)

    def test_legacy_booleans_alone_still_produce_a_target(self) -> None:
        # Audits committed before the collectors recorded addresses carry only
        # booleans. A detected Prometheus must still be checked on its default
        # port instead of reporting "not assessed".
        values = {
            "audit_data": {
                "healthChecks": {"monitoringStack": {"prometheus": True, "grafana": True}}
            }
        }
        endpoints, platforms = obs_discovery.endpoints_from_audit(values)
        self.assertEqual(
            sorted(e.url for e in endpoints),
            ["http://127.0.0.1:3000", "http://127.0.0.1:9090"],
        )
        self.assertEqual(sorted(platforms), ["grafana", "prometheus"])

    def test_missing_audit_evidence_is_not_an_error(self) -> None:
        self.assertEqual(obs_discovery.endpoints_from_audit({}), ([], []))
        self.assertEqual(
            obs_discovery.endpoints_from_audit({"audit_data": "broken"}), ([], [])
        )


class KubernetesDiscoveryTests(unittest.TestCase):
    def test_synthetic_helm_release_prefix_does_not_consume_the_target_budget(self) -> None:
        # Invent a full chart layout without copying any deployment inventory.
        prefix = "synthetic-prometheus-stack-"
        scrape_components = [
            "kubelet", "coredns", "kube-dns", "kube-state-metrics",
            "kube-proxy", "kube-controller-manager", "kube-scheduler",
            "metrics-server", "node-exporter", "operator", "alertmanager",
        ]
        items = [{
            "metadata": {"name": prefix + component, "namespace": "synthetic"},
            "spec": {"ports": [{"name": "http", "port": 9090}]},
        } for component in scrape_components]
        items += [{
            "metadata": {"name": prefix + component, "namespace": "synthetic"},
            "spec": {"ports": [{"name": "http", "port": port}]},
        } for component, port in (("grafana", 3000), ("prometheus", 9090))]
        result = obs_discovery.discover(
            {}, sockets="", processes="", services={"items": items}
        )
        self.assertEqual([(e.url, e.platform) for e in result.endpoints], [
            (f"http://{prefix}grafana.synthetic.svc.cluster.local:3000", "grafana"),
            (f"http://{prefix}prometheus.synthetic.svc.cluster.local:9090", "prometheus"),
        ])

    def test_release_tokens_cannot_claim_unrelated_service_components(self) -> None:
        for name in (
            "synthetic-prometheus-stack-kubelet",
            "synthetic-prometheus-stack-coredns",
            "synthetic-prometheus-stack-kube-state-metrics",
            "synthetic-grafana-stack-database",
            "synthetic-mimir-stack-memcached",
            "synthetic-vmselect-stack-kubelet",
            "synthetic-victoria-metrics-cluster-vmstorage",
            "synthetic-thanos-store",
            "synthetic-thanos-receive",
        ):
            with self.subTest(name=name):
                self.assertIsNone(obs_discovery._service_platform(name))

    def test_query_component_suffixes_identify_the_product(self) -> None:
        for name, platform in (
            ("kube-prometheus-stack-grafana", "grafana"),
            ("synthetic-vmselect-stack-grafana", "grafana"),
            ("kube-prometheus-stack-prometheus", "prometheus"),
            ("synthetic-prometheus-operated", "prometheus"),
            ("synthetic-prometheus-server", "prometheus"),
            ("synthetic-prometheus-k8s", "prometheus"),
            ("synthetic-thanos-query", "thanos"),
            ("synthetic-thanos-query-frontend", "thanos"),
            ("synthetic-vmselect", "vmselect"),
            ("synthetic-vmsingle", "victoriametrics"),
            ("synthetic-victoria-metrics-single-server", "victoriametrics"),
            ("synthetic-mimir-query-frontend", "mimir"),
            ("synthetic-cortex-querier", "cortex"),
        ):
            with self.subTest(name=name):
                self.assertEqual(obs_discovery._service_platform(name), platform)

    def test_https_metadata_survives_nonstandard_service_port(self) -> None:
        for port in (
            {"name": "https", "port": 8443},
            {"name": "web", "appProtocol": "https", "port": 9443},
        ):
            payload = {"items": [{
                "metadata": {"name": "grafana", "namespace": "monitoring"},
                "spec": {"ports": [port]},
            }]}
            endpoint, = obs_discovery.parse_kubernetes_services(payload)
            self.assertEqual(endpoint.url, f"https://grafana.monitoring.svc.cluster.local:{port['port']}")
    def test_named_web_port_wins_over_other_ports(self) -> None:
        payload = {
            "items": [
                {
                    "metadata": {"name": "kube-prom-grafana", "namespace": "monitoring"},
                    "spec": {"ports": [{"name": "metrics", "port": 8080}, {"name": "web", "port": 3000}]},
                },
                {
                    "metadata": {"name": "thanos-query", "namespace": "obs"},
                    "spec": {"ports": [{"port": 10902}]},
                },
                {
                    "metadata": {"name": "postgres", "namespace": "db"},
                    "spec": {"ports": [{"port": 5432}]},
                },
            ]
        }
        endpoints = obs_discovery.parse_kubernetes_services(payload)
        self.assertEqual(
            [(e.url, e.platform) for e in endpoints],
            [
                ("http://kube-prom-grafana.monitoring.svc.cluster.local:3000", "grafana"),
                ("http://thanos-query.obs.svc.cluster.local:10902", "thanos"),
            ],
        )

    def test_exporter_and_sidecar_services_are_not_query_targets(self) -> None:
        # These Service names all contain an include token but serve no query
        # API, so checking them spends the budget and names the wrong product.
        for name in (
            "kube-prom-prometheus-node-exporter",
            "nvidia-dcgm-exporter",
            "grafana-agent",
            "prometheus-adapter",
            "kube-prom-prometheus-operator",
            "kube-prom-alertmanager",
            "prometheus-pushgateway",
            "vminsert-cluster",
            "vmagent-cluster",
        ):
            payload = {
                "items": [
                    {
                        "metadata": {"name": name, "namespace": "monitoring"},
                        "spec": {"ports": [{"port": 9090}]},
                    }
                ]
            }
            self.assertEqual(obs_discovery.parse_kubernetes_services(payload), [], name)

    def test_real_backend_services_still_match(self) -> None:
        # prometheus-operated is the Service the Prometheus Operator creates for
        # the real server, so the "-operator" exclusion must not catch it.
        for name, platform in (
            ("prometheus-operated", "prometheus"),
            ("prometheus-server", "prometheus"),
            ("vmselect-cluster", "vmselect"),
            ("mimir-query-frontend", "mimir"),
            ("kube-prom-grafana", "grafana"),
        ):
            payload = {
                "items": [
                    {
                        "metadata": {"name": name, "namespace": "monitoring"},
                        "spec": {"ports": [{"port": 9090}]},
                    }
                ]
            }
            endpoints = obs_discovery.parse_kubernetes_services(payload)
            self.assertEqual([e.platform for e in endpoints], [platform], name)


class DiscoverOrderingTests(unittest.TestCase):
    def test_audit_evidence_ranks_before_local_and_cluster_vantages(self) -> None:
        values = {
            "audit_data": {
                "healthChecks": {"monitoringStack": {"endpoints": ["10.0.0.5:9090"]}}
            }
        }
        services = {
            "items": [
                {
                    "metadata": {"name": "grafana", "namespace": "monitoring"},
                    "spec": {"ports": [{"port": 3000}]},
                }
            ]
        }
        result = obs_discovery.discover(
            values, sockets="0.0.0.0:8428\n", processes="", services=services
        )
        self.assertEqual(
            result.urls(),
            [
                "http://10.0.0.5:9090",
                "http://127.0.0.1:8428",
                "http://grafana.monitoring.svc.cluster.local:3000",
            ],
        )
        self.assertEqual(result.source_label(), "audit+sockets+k8s-services")

    def test_duplicate_endpoints_collapse_to_one_target(self) -> None:
        values = {
            "audit_data": {
                "healthChecks": {"monitoringStack": {"endpoints": ["0.0.0.0:9090"]}}
            }
        }
        result = obs_discovery.discover(
            values, sockets="0.0.0.0:9090\n", processes="prometheus\n", services={}
        )
        self.assertEqual(result.urls(), ["http://127.0.0.1:9090"])
        self.assertEqual(result.source_label(), "audit")

    def test_no_evidence_yields_no_targets(self) -> None:
        result = obs_discovery.discover({}, sockets="", processes="", services={})
        self.assertEqual(result.urls(), [])
        self.assertEqual(result.source_label(), "none")

    def test_target_budget_is_capped(self) -> None:
        sockets = "\n".join(f"10.0.0.{index}:9090" for index in range(1, 20))
        result = obs_discovery.discover(
            {}, sockets=sockets, processes="", services={}, max_targets=3
        )
        self.assertEqual(len(result.urls()), 3)

    def test_a_vantage_whose_targets_all_fall_past_the_cap_is_not_reported(self) -> None:
        # The source label describes what was checked. Claiming a vantage that
        # contributed no checked target misdescribes the result.
        values = {
            "audit_data": {
                "healthChecks": {
                    "monitoringStack": {"endpoints": ["10.0.0.1:9090", "10.0.0.2:3000"]}
                }
            }
        }
        services = {
            "items": [
                {
                    "metadata": {"name": "grafana", "namespace": "monitoring"},
                    "spec": {"ports": [{"port": 3000}]},
                }
            ]
        }
        result = obs_discovery.discover(
            values, sockets="", processes="", services=services, max_targets=2
        )
        self.assertEqual(result.source_label(), "audit")
        self.assertEqual(len(result.urls()), 2)
        # The platform is still recorded, because discovery did see it.
        self.assertIn("grafana", result.platforms)


if __name__ == "__main__":
    unittest.main()


class RemoteVantageTests(unittest.TestCase):
    def test_remote_kubernetes_audit_skips_this_machine(self) -> None:
        values = {
            "audit_data": {
                "healthChecks": {
                    "monitoringStack": {
                        "prometheus": True,
                        "endpoints": ["127.0.0.1:3000", "10.0.0.5:9090"],
                    }
                }
            }
        }
        result = obs_discovery.discover(
            values,
            sockets="0.0.0.0:8428\n",
            processes="",
            services={},
            local_vantage=False,
        )
        self.assertEqual(result.urls(), ["http://10.0.0.5:9090"])
        self.assertIn("prometheus", result.platforms)

    def test_boolean_evidence_alone_yields_no_remote_target(self) -> None:
        values = {"audit_data": {"healthChecks": {"monitoringStack": {"prometheus": True}}}}
        result = obs_discovery.discover(values, services={}, local_vantage=False)
        self.assertEqual(result.urls(), [])
        self.assertEqual(result.platforms, ("prometheus",))

    def test_local_vantage_keeps_default_port_fallback(self) -> None:
        values = {"audit_data": {"healthChecks": {"monitoringStack": {"prometheus": True}}}}
        result = obs_discovery.discover(values, sockets="", processes="", services={})
        self.assertEqual(result.urls(), ["http://127.0.0.1:9090"])
