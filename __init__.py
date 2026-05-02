"""
黄客联盟 · 渗透测试工具箱 v3.0
HuangKe Alliance — Red Team Web Penetration Toolkit
目录扫描 | 指纹识别 | 端口扫描 | 内容分析 | 信息收集
"""

__version__ = "3.0.0"
__author__ = "黄客联盟 (HuangKe Alliance)"
__description__ = "Red Team Web Penetration Toolkit"

from .main import main, main_async

__all__ = ["main", "main_async", "__version__"]
