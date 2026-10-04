"""
反作弊与硬件指纹系统 - 核心模块

功能：
- generate_fingerprint(): 多硬件组件指纹生成，确定性、持久化、防篡改
- vm_detection(): 虚拟机检测（MAC OUI / 硬件特征字符串 / hypervisor 标志 / 行为时序分析）
- multi_instance_detection(): 多开检测（互斥体 / 进程名 / 进程路径 / 窗口枚举含隐藏窗口）
- debugger_detection(): 调试器检测（多种 API 标志 / 硬件断点 DR 寄存器 / 时序检查）
- memory_integrity(): 内存完整性（HMAC 加密校验基线 / 篡改告警 / update() 定时检查）
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
import hashlib
import hmac
import json
import math
import os
import platform
import statistics
import time


@dataclass
class Config:
    pass


class HardwareFingerprint:
    HARDWARE_COMPONENTS: Tuple[str, ...] = (
        "cpu_model",
        "motherboard",
        "disk_serial",
        "mac_address",
        "bios_version",
    )

    VM_MAC_PREFIXES: Tuple[str, ...] = (
        "00:0c:29", "00:50:56", "00:05:69",  # VMware
        "08:00:27",                          # VirtualBox
        "00:15:5d",                          # Hyper-V
        "00:1c:42",                          # Parallels
        "52:54:00",                          # KVM/QEMU
    )

    VM_VENDOR_KEYWORDS: Tuple[str, ...] = (
        "vmware", "virtualbox", "vbox", "virtual machine", "virtual",
        "hyper-v", "microsoft hv", "kvm", "qemu", "xen", "parallels",
        "bochs", "innotek",
    )

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._state = {}
        self._history = []
        self.alerts: List[Dict] = []
        self._fingerprint: Optional[str] = None
        self._integrity_key = os.urandom(32)
        self._memory_baseline: Dict[str, bytes] = {}
        self._memory_provider: Optional[Callable[[], Dict[str, bytes]]] = None
        self._storage_path = self.config.get(
            "storage_path",
            os.path.join(os.path.expanduser("~"), ".hw_fingerprint.json"),
        )

    # ------------------------------------------------------------------
    # 硬件指纹
    # ------------------------------------------------------------------
    def generate_fingerprint(self, hardware_info: Optional[Dict] = None) -> Dict:
        """基于 CPU/主板/硬盘/MAC/BIOS 多组件生成确定性指纹并持久化。"""
        info = dict(hardware_info) if hardware_info else self._collect_hardware_info()
        components = {
            name: self._normalize(info.get(name)) for name in self.HARDWARE_COMPONENTS
        }
        material = "|".join(f"{k}={components[k]}" for k in sorted(components))
        computed = hashlib.sha256(material.encode("utf-8")).hexdigest()
        key = self._storage_key(material)

        fingerprint = computed
        persisted = False
        tampered = False
        stored = self._load_stored(key)
        if stored is not None:
            if stored["valid"]:
                fingerprint = stored["fingerprint"]
                persisted = True
            else:
                tampered = True
        if not persisted:
            self._store_fingerprint(fingerprint, key)

        self._fingerprint = fingerprint
        result = {
            "fingerprint": fingerprint,
            "components": sorted(components),
            "persisted": persisted,
            "tampered": tampered,
        }
        self._history.append({"type": "fingerprint", "time": time.time(), **result})
        return result

    @staticmethod
    def _normalize(value) -> str:
        if value is None:
            return "unknown"
        text = str(value).strip().lower()
        return text if text else "unknown"

    @staticmethod
    def _storage_key(material: str) -> bytes:
        return hashlib.sha256(("hwfp-storage-key|" + material).encode("utf-8")).digest()

    def _store_fingerprint(self, fingerprint: str, key: bytes):
        signature = hmac.new(key, fingerprint.encode("utf-8"), hashlib.sha256).hexdigest()
        payload = {"fingerprint": fingerprint, "signature": signature}
        try:
            directory = os.path.dirname(self._storage_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(self._storage_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
        except OSError:
            pass

    def _load_stored(self, key: bytes) -> Optional[Dict]:
        if not os.path.exists(self._storage_path):
            return None
        try:
            with open(self._storage_path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            fingerprint = payload["fingerprint"]
            signature = payload["signature"]
        except (OSError, ValueError, KeyError, TypeError):
            return {"valid": False, "fingerprint": None}
        expected = hmac.new(key, fingerprint.encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, signature):
            return {"valid": True, "fingerprint": fingerprint}
        return {"valid": False, "fingerprint": None}

    def _collect_hardware_info(self) -> Dict:
        info = {"cpu_model": platform.processor() or platform.machine()}
        try:
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        if line.lower().startswith("model name"):
                            info["cpu_model"] = line.split(":", 1)[1].strip()
                            break
        except OSError:
            pass
        return info

    # ------------------------------------------------------------------
    # 虚拟机检测
    # ------------------------------------------------------------------
    def vm_detection(
        self,
        system_info: Optional[Dict] = None,
        timing_samples: Optional[List[float]] = None,
    ) -> Dict:
        """多指标虚拟机检测：MAC OUI、硬件特征字符串、hypervisor 标志、行为时序分析。"""
        info = system_info or {}
        indicators: List[str] = []
        score = 0

        mac = self._normalize(info.get("mac_address")).replace("-", ":")
        if any(mac.startswith(prefix) for prefix in self.VM_MAC_PREFIXES):
            indicators.append("vm_mac_prefix")
            score += 40

        for field_name in (
            "cpu_model",
            "bios_vendor",
            "disk_model",
            "motherboard_manufacturer",
            "system_manufacturer",
            "system_model",
        ):
            value = self._normalize(info.get(field_name))
            if any(keyword in value for keyword in self.VM_VENDOR_KEYWORDS):
                indicators.append("vm_" + field_name)
                score += 25

        if info.get("hypervisor_flag"):
            indicators.append("hypervisor_flag")
            score += 30

        behavioral = False
        if timing_samples and len(timing_samples) >= 2:
            mean = statistics.fmean(timing_samples)
            stdev = statistics.pstdev(timing_samples)
            cv_threshold = self.config.get("vm_timing_cv_threshold", 0.5)
            if mean > 0 and stdev / mean > cv_threshold:
                behavioral = True
                indicators.append("timing_anomaly")
                score += 20

        threshold = self.config.get("vm_score_threshold", 40)
        is_vm = score >= threshold
        result = {
            "is_vm": is_vm,
            "score": score,
            "indicators": indicators,
            "behavioral": behavioral,
        }
        self._history.append({"type": "vm_detection", "time": time.time(), **result})
        return result

    # ------------------------------------------------------------------
    # 多开检测
    # ------------------------------------------------------------------
    def multi_instance_detection(
        self,
        processes: Optional[List] = None,
        windows: Optional[List] = None,
        mutexes: Optional[List[str]] = None,
    ) -> Dict:
        """多开检测：互斥体 + 进程名 + 进程路径（抓改名）+ 窗口枚举（含隐藏窗口）。"""
        own_name = self.config.get("process_name", "game.exe").lower()
        own_path = (self.config.get("process_path") or "").lower()
        own_title = self.config.get("window_title", "game").lower()
        own_mutex = self.config.get("mutex_name", "Global\\GameGuardMutex")

        methods: List[str] = []

        if mutexes and own_mutex in mutexes:
            methods.append("mutex")

        process_matches = 0
        renamed_found = False
        name_found = False
        for proc in processes or []:
            if isinstance(proc, str):
                proc = {"name": proc}
            pname = (proc.get("name") or "").lower()
            ppath = (proc.get("path") or "").lower()
            by_name = pname == own_name
            by_path = bool(own_path) and ppath == own_path
            if by_name or by_path:
                process_matches += 1
                if by_name:
                    name_found = True
                elif by_path:
                    renamed_found = True
        if name_found:
            methods.append("process_name")
        if renamed_found:
            methods.append("process_path")

        window_matches = 0
        hidden_found = False
        for window in windows or []:
            if isinstance(window, str):
                window = {"title": window}
            title = (window.get("title") or "").lower()
            if own_title and own_title in title:
                window_matches += 1
                if not window.get("visible", True):
                    hidden_found = True
        if window_matches:
            methods.append("window_enum")
        if hidden_found:
            methods.append("hidden_window")

        instance_count = max(process_matches, window_matches, 1 if "mutex" in methods else 0)
        multiple = instance_count > 1 or "mutex" in methods
        result = {
            "multiple_instances": multiple,
            "instance_count": instance_count,
            "methods": methods,
        }
        self._history.append({"type": "multi_instance", "time": time.time(), **result})
        return result

    # ------------------------------------------------------------------
    # 调试器检测
    # ------------------------------------------------------------------
    def debugger_detection(
        self,
        is_debugger_present: Optional[bool] = None,
        remote_debugger: Optional[bool] = None,
        nt_global_flag: Optional[bool] = None,
        debug_registers: Optional[Dict] = None,
        timing: Optional[Tuple[float, float]] = None,
    ) -> Dict:
        """调试器检测：多种 API 标志 + 硬件断点（DR0-DR7）+ 时序检查。"""
        methods: List[str] = []

        if is_debugger_present:
            methods.append("is_debugger_present")
        if remote_debugger:
            methods.append("remote_debugger")
        if nt_global_flag:
            methods.append("nt_global_flag")

        if debug_registers:
            dr7 = int(debug_registers.get("dr7", 0) or 0)
            hw_breakpoints = [
                reg
                for reg in ("dr0", "dr1", "dr2", "dr3")
                if debug_registers.get(reg)
            ]
            if hw_breakpoints and (dr7 & 0xFF):
                methods.append("hardware_breakpoint")

        if timing:
            expected, actual = timing
            threshold = self.config.get("debug_timing_threshold", 10.0)
            if expected > 0 and actual > expected * threshold:
                methods.append("timing_check")

        detected = bool(methods)
        result = {"debugger_detected": detected, "methods": methods}
        if detected:
            self._history.append({"type": "debugger", "time": time.time(), **result})
        return result

    # ------------------------------------------------------------------
    # 内存完整性
    # ------------------------------------------------------------------
    def memory_integrity(self, regions: Optional[Dict[str, bytes]] = None) -> Dict:
        """首次调用建立加密校验基线，后续调用校验并报告篡改区域。"""
        regions = regions or {}
        if not self._memory_baseline:
            for name, data in regions.items():
                self._memory_baseline[name] = self._region_checksum(name, data)
            return {
                "baseline_established": True,
                "intact": True,
                "regions": sorted(self._memory_baseline),
                "tampered_regions": [],
            }
        return self._verify_regions(regions)

    def set_memory_provider(self, provider: Callable[[], Dict[str, bytes]]):
        """注册内存区域提供者，供 update() 定时校验使用。"""
        self._memory_provider = provider

    def _region_checksum(self, name: str, data) -> bytes:
        keyed = hmac.new(
            self._integrity_key,
            name.encode("utf-8") + b"\x00" + bytes(data),
            hashlib.sha256,
        ).digest()
        return self._obfuscate(keyed)

    def _obfuscate(self, digest: bytes) -> bytes:
        stream = hashlib.sha256(self._integrity_key + b"storage-mask").digest()
        return bytes(a ^ b for a, b in zip(digest, stream))

    def _verify_regions(self, regions: Dict[str, bytes]) -> Dict:
        tampered = []
        for name, stored in self._memory_baseline.items():
            data = regions.get(name)
            if data is None or self._region_checksum(name, data) != stored:
                tampered.append(name)
        result = {
            "baseline_established": False,
            "intact": not tampered,
            "regions": sorted(self._memory_baseline),
            "tampered_regions": tampered,
        }
        if tampered:
            alert = {
                "type": "memory_integrity",
                "time": time.time(),
                "tampered_regions": list(tampered),
            }
            self._history.append(alert)
            self.alerts.append(alert)
        return result

    # ------------------------------------------------------------------
    # 周期驱动
    # ------------------------------------------------------------------
    def update(self, dt: float):
        """累积时间，到达完整性检查间隔时自动执行内存校验。"""
        interval = self.config.get("integrity_check_interval", 5.0)
        elapsed = self._state.get("integrity_elapsed", 0.0) + dt
        if self._memory_provider is not None and elapsed >= interval:
            elapsed = 0.0
            self._verify_regions(self._memory_provider())
        self._state["integrity_elapsed"] = elapsed

    def get_alerts(self) -> List[Dict]:
        return list(self.alerts)

    def reset(self):
        self._state = {}
        self._history = []
        self.alerts = []
        self._fingerprint = None
        self._memory_baseline = {}
        self._memory_provider = None
