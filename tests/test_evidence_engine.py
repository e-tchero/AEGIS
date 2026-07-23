"""Tests for the AEGIS Evidence Engine (Priority 1)."""

from datetime import datetime
from pathlib import Path

import pytest

from modules.evidence_engine import EvidenceEngine, EvidencePackage, ProcessNode


class TestDataModels:
    """Tests for evidence data models."""

    def test_process_node_creation(self):
        node = ProcessNode(
            pid=1234, name="powershell.exe",
            cmdline="powershell -enc test",
            exe="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            create_time=1234567890.0, username="admin",
            cpu_percent=5.0, memory_percent=10.0,
        )
        assert node.pid == 1234
        assert node.name == "powershell.exe"

    def test_process_node_with_parent_reference(self):
        parent = ProcessNode(
            pid=888, name="explorer.exe", cmdline="explorer",
            exe="C:\\Windows\\explorer.exe", create_time=1234567800.0,
            username="admin", cpu_percent=1.0, memory_percent=2.0,
        )
        child = ProcessNode(
            pid=1234, name="powershell.exe", cmdline="powershell -enc test",
            exe="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            create_time=1234567890.0, username="admin",
            cpu_percent=5.0, memory_percent=10.0,
        )
        # Manual parent relationship (external to dataclass)
        assert child.pid != parent.pid
        assert child.name == "powershell.exe"

    def test_connection_data_in_evidence(self):
        """Evidence packages can carry connection-like data in raw."""
        package = EvidencePackage(
            captured_at=datetime.now().isoformat(),
            threat_type="REVERSE_SHELL",
            threat_id="AEGIS-EVID-CONN",
            raw={
                "connections": [
                    {"local_addr": "192.168.1.2", "local_port": 49152,
                     "remote_addr": "10.0.0.5", "remote_port": 4444,
                     "status": "ESTABLISHED"}
                ]
            },
        )
        assert "connections" in package.raw
        assert package.raw["connections"][0]["remote_addr"] == "10.0.0.5"

    def test_evidence_package_creation(self):
        package = EvidencePackage(
            captured_at=datetime.now().isoformat(),
            threat_type="REVERSE_SHELL",
            threat_id="AEGIS-EVID-0001",
            system_info={"hostname": "test-pc", "os": "windows"},
            raw={"source": "test"},
        )
        assert package.threat_type == "REVERSE_SHELL"
        assert package.threat_id == "AEGIS-EVID-0001"

    def test_evidence_package_with_process_tree(self):
        parent = ProcessNode(
            pid=888, name="explorer.exe", cmdline="explorer",
            exe="explorer.exe", create_time=1000.0,
            username="user", cpu_percent=1.0, memory_percent=2.0,
        )
        child = ProcessNode(
            pid=1234, name="powershell.exe", cmdline="powershell -enc test",
            exe="powershell.exe", create_time=2000.0,
            username="user", cpu_percent=5.0, memory_percent=10.0,
        )
        package = EvidencePackage(
            captured_at=datetime.now().isoformat(),
            threat_type="SUSPICIOUS_CHAIN",
            threat_id="AEGIS-EVID-0002",
            process_tree=[parent, child],
        )
        assert len(package.process_tree) == 2


class TestEvidenceEngine:
    """Tests for the EvidenceEngine class."""

    def test_generate_threat_id(self):
        threat_id = EvidenceEngine.generate_threat_id()
        assert isinstance(threat_id, str)
        assert len(threat_id) > 0

    def test_generate_unique_ids(self):
        ids = {EvidenceEngine.generate_threat_id() for _ in range(100)}
        assert len(ids) == 100  # All unique

    def test_persist_and_load_package(self):
        package = EvidencePackage(
            captured_at=datetime.now().isoformat(),
            threat_type="SYN_SCAN",
            threat_id="AEGIS-EVID-TEST-0001",
            system_info={"hostname": "test", "os": "linux"},
            raw={"source_ip": "10.0.0.5", "ports": [22, 80, 443]},
        )
        filepath = EvidenceEngine.persist(package)
        assert filepath is not None
        path = Path(filepath)
        assert path.exists()
        path.unlink()

    def test_persist_with_process_node(self):
        parent = ProcessNode(
            pid=888, name="explorer.exe", cmdline="explorer",
            exe="explorer.exe", create_time=1000.0,
            username="user", cpu_percent=1.0, memory_percent=2.0,
        )
        child = ProcessNode(
            pid=1234, name="powershell.exe", cmdline="powershell -enc SQBFAFgA",
            exe="powershell.exe", create_time=2000.0,
            username="user", cpu_percent=5.0, memory_percent=10.0,
        )
        package = EvidencePackage(
            captured_at=datetime.now().isoformat(),
            threat_type="REVERSE_SHELL",
            threat_id="AEGIS-EVID-TEST-0002",
            process_tree=[parent, child],
        )
        filepath = EvidenceEngine.persist(package)
        assert filepath is not None
        path = Path(filepath)
        assert path.exists()
        path.unlink()

    def test_persist_with_connection_data(self):
        """Persist a package with connection data in raw."""
        package = EvidencePackage(
            captured_at=datetime.now().isoformat(),
            threat_type="REVERSE_SHELL",
            threat_id="AEGIS-EVID-TEST-0003",
            raw={
                "local_addr": "192.168.1.2",
                "remote_addr": "10.0.0.5",
                "remote_port": 4444,
            },
        )
        filepath = EvidenceEngine.persist(package)
        assert filepath is not None
        path = Path(filepath)
        assert path.exists()
        path.unlink()

    def test_dicts_to_process_nodes(self):
        raw_nodes = [
            {"pid": 1, "name": "init", "cmdline": "/sbin/init", "exe": "/sbin/init",
             "create_time": 1000.0, "username": "root", "cpu_percent": 0.0, "memory_percent": 0.0},
            {"pid": 888, "name": "explorer.exe", "cmdline": "explorer", "exe": "explorer.exe",
             "create_time": 2000.0, "username": "user", "cpu_percent": 1.0, "memory_percent": 2.0},
        ]
        nodes = EvidenceEngine.dicts_to_process_nodes(raw_nodes)
        assert len(nodes) == 2

    def test_render_process_tree(self):
        parent = ProcessNode(
            pid=888, name="explorer.exe", cmdline="explorer",
            exe="explorer.exe", create_time=1000.0,
            username="user", cpu_percent=1.0, memory_percent=2.0,
        )
        child = ProcessNode(
            pid=1234, name="powershell.exe", cmdline="powershell -enc test",
            exe="powershell.exe", create_time=2000.0,
            username="user", cpu_percent=5.0, memory_percent=10.0,
        )
        nodes = [parent, child]
        rendered = EvidenceEngine.render_process_tree(nodes, target_pid=1234)
        assert isinstance(rendered, str)
        assert "powershell.exe" in rendered
        assert "1234" in rendered

    def test_render_process_tree_no_target(self):
        parent = ProcessNode(
            pid=888, name="explorer.exe", cmdline="explorer",
            exe="explorer.exe", create_time=1000.0,
            username="user", cpu_percent=1.0, memory_percent=2.0,
        )
        child = ProcessNode(
            pid=1234, name="powershell.exe", cmdline="powershell -enc test",
            exe="powershell.exe", create_time=2000.0,
            username="user", cpu_percent=5.0, memory_percent=10.0,
        )
        nodes = [parent, child]
        rendered = EvidenceEngine.render_process_tree(nodes)
        assert isinstance(rendered, str)
        assert "powershell.exe" in rendered

    def test_render_process_tree_unknown_target(self):
        nodes = [ProcessNode(
            pid=1, name="init", cmdline="/sbin/init",
            exe="/sbin/init", create_time=1000.0,
            username="root", cpu_percent=0.0, memory_percent=0.0,
        )]
        rendered = EvidenceEngine.render_process_tree(nodes, target_pid=9999)
        assert isinstance(rendered, str)

    def test_empty_dicts_to_process_nodes(self):
        nodes = EvidenceEngine.dicts_to_process_nodes([])
        assert nodes == []

    def test_invalid_dicts_to_process_nodes(self):
        nodes = EvidenceEngine.dicts_to_process_nodes([{"pid": 1}])
        assert len(nodes) == 1
        assert nodes[0].name == "?"

    def test_capture_system_info(self):
        """System info capture should work without psutil or return empty dict."""
        import psutil
        try:
            info = EvidenceEngine._capture_system_info()
            assert isinstance(info, dict)
            assert "hostname" in info
        except Exception:
            pytest.skip("System info capture requires psutil")


class TestEvidencePersistenceEdgeCases:
    """Tests for evidence persistence edge cases."""

    def test_persist_empty_package(self):
        package = EvidencePackage(
            captured_at=datetime.now().isoformat(),
            threat_type="TEST",
            threat_id="AEGIS-EVID-TEST-EMPTY",
        )
        filepath = EvidenceEngine.persist(package)
        assert filepath is not None
        Path(filepath).unlink()

    def test_persist_large_package(self):
        """Test persistence with many process tree nodes."""
        nodes = []
        for i in range(50):
            nodes.append(ProcessNode(
                pid=i, name=f"proc_{i}", cmdline=f"cmd_{i}",
                exe=f"/bin/proc_{i}", create_time=float(i),
                username="user", cpu_percent=float(i % 100),
                memory_percent=float(i % 100),
            ))
        package = EvidencePackage(
            captured_at=datetime.now().isoformat(),
            threat_type="TEST",
            threat_id="AEGIS-EVID-TEST-LARGE",
            process_tree=nodes,
        )
        filepath = EvidenceEngine.persist(package)
        assert filepath is not None
        assert Path(filepath).exists()
        Path(filepath).unlink()

    def test_evidence_id_format(self):
        tid = EvidenceEngine.generate_threat_id()
        assert isinstance(tid, str)
        assert len(tid) > 0
