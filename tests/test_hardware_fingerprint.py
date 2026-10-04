"""
反作弊与硬件指纹系统 - 验收测试
运行方式：python -m pytest tests/test_hardware_fingerprint.py -q
共 16 个测试用例
"""
import hashlib
import json
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anticheat.hardware_fingerprint import HardwareFingerprint


BASE_HARDWARE = {
    "cpu_model": "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz",
    "motherboard": "ASUSTeK ROG STRIX B360-G",
    "disk_serial": "SamsungSSD970-EVO-SN1234567890",
    "mac_address": "3C:52:82:11:22:33",
    "bios_version": "American Megatrends BIOS 2401",
}


class TestHardwareFingerprint:
    def setup_method(self):
        self.system = HardwareFingerprint()

    # ---- 指纹生成（4）----
    def test_case_01(self):
        """指纹生成是确定性的，不含随机数，多次生成完全一致。"""
        first = self.system.generate_fingerprint(BASE_HARDWARE)
        second = self.system.generate_fingerprint(BASE_HARDWARE)
        third = self.system.generate_fingerprint(BASE_HARDWARE)
        assert len(first["fingerprint"]) == 64
        assert first["fingerprint"] == second["fingerprint"] == third["fingerprint"]

    def test_case_02(self):
        """指纹综合 CPU/主板/硬盘/MAC/BIOS，任一硬件变化都会改变指纹。"""
        base = self.system.generate_fingerprint(BASE_HARDWARE)["fingerprint"]
        for component in ("cpu_model", "motherboard", "disk_serial",
                          "mac_address", "bios_version"):
            changed = dict(BASE_HARDWARE)
            changed[component] = BASE_HARDWARE[component] + "-changed"
            fp = self.system.generate_fingerprint(changed)["fingerprint"]
            assert fp != base, f"{component} 未参与指纹计算"

    def test_case_03(self, tmp_path):
        """指纹持久化：重启后新实例从存储恢复同一指纹。"""
        storage = str(tmp_path / "fingerprint.json")
        first = HardwareFingerprint({"storage_path": storage})
        fp1 = first.generate_fingerprint(BASE_HARDWARE)
        assert fp1["persisted"] is False
        assert os.path.exists(storage)

        restarted = HardwareFingerprint({"storage_path": storage})
        fp2 = restarted.generate_fingerprint(BASE_HARDWARE)
        assert fp2["persisted"] is True
        assert fp2["fingerprint"] == fp1["fingerprint"]

    def test_case_04(self, tmp_path):
        """持久化文件被玩家篡改时能识别并重新生成。"""
        storage = str(tmp_path / "fingerprint.json")
        system = HardwareFingerprint({"storage_path": storage})
        original = system.generate_fingerprint(BASE_HARDWARE)

        with open(storage, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        payload["fingerprint"] = "a" * 64
        with open(storage, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

        restarted = HardwareFingerprint({"storage_path": storage})
        result = restarted.generate_fingerprint(BASE_HARDWARE)
        assert result["tampered"] is True
        assert result["fingerprint"] == original["fingerprint"]

    # ---- 虚拟机检测（3）----
    def test_case_05(self):
        """VMware 通过 MAC OUI 和硬件特征字符串被检出。"""
        vmware = {
            "cpu_model": "Intel(R) Xeon(R) Gold 6230 CPU @ 2.10GHz",
            "mac_address": "00:0C:29:AA:BB:CC",
            "bios_vendor": "VMware, Inc.",
            "disk_model": "VMware Virtual S",
            "motherboard_manufacturer": "VMware, Inc.",
            "hypervisor_flag": True,
        }
        result = self.system.vm_detection(vmware)
        assert result["is_vm"] is True
        assert "vm_mac_prefix" in result["indicators"]
        assert result["score"] >= 40

    def test_case_06(self):
        """VirtualBox 与 Hyper-V 同样能被检出。"""
        virtualbox = {
            "mac_address": "08:00:27:12:34:56",
            "bios_vendor": "innotek GmbH VirtualBox",
            "disk_model": "VBOX HARDDISK",
        }
        hyperv = {
            "mac_address": "00:15:5D:01:02:03",
            "system_manufacturer": "Microsoft Corporation",
            "system_model": "Virtual Machine",
        }
        assert self.system.vm_detection(virtualbox)["is_vm"] is True
        assert self.system.vm_detection(hyperv)["is_vm"] is True

    def test_case_07(self):
        """行为时序分析：虚拟机抖动被标记；物理机稳定时序不误报。"""
        physical = {
            "cpu_model": "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz",
            "mac_address": "3C:52:82:11:22:33",
            "bios_vendor": "American Megatrends BIOS 2401",
            "disk_model": "Samsung SSD 970 EVO",
        }
        stable = [0.0010, 0.0011, 0.0009, 0.0010, 0.0010]
        clean = self.system.vm_detection(physical, timing_samples=stable)
        assert clean["is_vm"] is False
        assert clean["behavioral"] is False

        jittery = [0.0010, 0.0050, 0.0008, 0.0035, 0.0090]
        suspicious = self.system.vm_detection(physical, timing_samples=jittery)
        assert suspicious["behavioral"] is True
        assert "timing_anomaly" in suspicious["indicators"]

    # ---- 多开检测（3）----
    def test_case_08(self):
        """互斥体已被其他实例占用时检出多开。"""
        result = self.system.multi_instance_detection(
            processes=[], windows=[],
            mutexes=["Global\\SomeOtherMutex", "Global\\GameGuardMutex"],
        )
        assert result["multiple_instances"] is True
        assert "mutex" in result["methods"]

    def test_case_09(self):
        """进程名重复检出多开；玩家改名后仍可通过进程路径抓到。"""
        by_name = self.system.multi_instance_detection(
            processes=[
                {"pid": 1000, "name": "game.exe", "path": "C:\\game\\game.exe"},
                {"pid": 2000, "name": "game.exe", "path": "D:\\copy\\game.exe"},
            ]
        )
        assert by_name["multiple_instances"] is True
        assert by_name["instance_count"] == 2
        assert "process_name" in by_name["methods"]

        config = {"process_name": "game.exe", "process_path": "C:\\game\\game.exe"}
        renamed = HardwareFingerprint(config).multi_instance_detection(
            processes=[
                {"pid": 1000, "name": "game.exe", "path": "C:\\game\\game.exe"},
                {"pid": 2000, "name": "notavirus.exe", "path": "C:\\game\\game.exe"},
            ]
        )
        assert renamed["multiple_instances"] is True
        assert "process_path" in renamed["methods"]

    def test_case_10(self):
        """窗口枚举能发现隐藏窗口中的另一个客户端。"""
        result = self.system.multi_instance_detection(
            processes=[{"pid": 1000, "name": "game.exe", "path": "C:\\game\\game.exe"}],
            windows=[
                {"title": "My Game", "visible": True},
                {"title": "My Game (multi)", "visible": False},
            ],
        )
        assert result["multiple_instances"] is True
        assert "window_enum" in result["methods"]
        assert "hidden_window" in result["methods"]

    # ---- 调试器检测（3）----
    def test_case_11(self):
        """多种调试器 API 标志（IsDebuggerPresent / 远程调试器 / NtGlobalFlag）。"""
        assert self.system.debugger_detection(is_debugger_present=True)["debugger_detected"]
        result = self.system.debugger_detection(
            remote_debugger=True, nt_global_flag=True
        )
        assert "remote_debugger" in result["methods"]
        assert "nt_global_flag" in result["methods"]
        clean = self.system.debugger_detection(
            is_debugger_present=False, remote_debugger=False
        )
        assert clean["debugger_detected"] is False

    def test_case_12(self):
        """CE 设置的硬件断点通过 DR0-DR7 调试寄存器检出。"""
        registers = {"dr0": 0x7FF612340000, "dr1": 0, "dr2": 0, "dr3": 0,
                     "dr7": 0b00000001}
        result = self.system.debugger_detection(debug_registers=registers)
        assert result["debugger_detected"] is True
        assert "hardware_breakpoint" in result["methods"]

        unused = {"dr0": 0, "dr1": 0, "dr2": 0, "dr3": 0, "dr7": 0}
        assert self.system.debugger_detection(debug_registers=unused)["debugger_detected"] is False

    def test_case_13(self):
        """时序检查：检测后再附加调试器单步执行导致耗时暴增时被发现。"""
        result = self.system.debugger_detection(timing=(0.001, 0.25))
        assert result["debugger_detected"] is True
        assert "timing_check" in result["methods"]
        clean = self.system.debugger_detection(timing=(0.001, 0.0011))
        assert clean["debugger_detected"] is False

    # ---- 内存完整性（3）----
    def test_case_14(self):
        """内存完整性实际生效：篡改区域在校验时被报告并产生告警。"""
        regions = {"score": b"100", "coins": b"5000"}
        baseline = self.system.memory_integrity(regions)
        assert baseline["baseline_established"] is True

        intact = self.system.memory_integrity(regions)
        assert intact["intact"] is True
        assert intact["tampered_regions"] == []

        tampered_regions = {"score": b"999", "coins": b"5000"}
        result = self.system.memory_integrity(tampered_regions)
        assert result["intact"] is False
        assert "score" in result["tampered_regions"]
        assert self.system.get_alerts()

    def test_case_15(self):
        """校验值加密：基线不是明文哈希，玩家无法伪造通过校验。"""
        regions = {"score": b"100"}
        self.system.memory_integrity(regions)
        stored = self.system._memory_baseline["score"]
        plain_hash = hashlib.sha256(b"score\x00" + b"100").digest()
        assert stored != plain_hash

        forged_regions = {"score": b"99999"}
        self.system._memory_baseline["score"] = hashlib.sha256(
            b"score\x00" + b"99999"
        ).digest()
        result = self.system.memory_integrity(forged_regions)
        assert result["intact"] is False

    def test_case_16(self):
        """定时检查：游戏运行过程中改内存，update() 周期性校验会告警。"""
        regions = {"score": b"100", "coins": b"5000"}
        system = HardwareFingerprint({"integrity_check_interval": 1.0})
        system.memory_integrity(regions)
        live = dict(regions)
        system.set_memory_provider(lambda: live)

        system.update(0.5)
        assert system.get_alerts() == []

        live["coins"] = b"999999"
        system.update(0.4)
        assert system.get_alerts() == []

        system.update(0.2)
        alerts = system.get_alerts()
        assert alerts and "coins" in alerts[-1]["tampered_regions"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
