# 反作弊与硬件指纹系统

## 项目描述

反作弊与硬件指纹系统的bug修复项目。核心模块 `anticheat/hardware_fingerprint.py` 存在多个已知bug，需要修复后使测试全部通过。

## 已知问题

- 指纹生成只用CPU型号不考虑主板硬盘MAC
- 虚拟机检测完全没做VMware都检测不到
- 多开检测只用互斥体玩家可改名绕过
- 调试器检测只用IsDebuggerPresent易绕过
- 内存完整性完全没做玩家改内存不告警

## 运行测试

```bash
python -m pytest tests/test_hardware_fingerprint.py -q
```

修复目标：所有 16 个测试全部通过。

## 技术要求

- 纯Python标准库，不引入第三方依赖
- 不修改测试文件
- 保持现有API接口不变
