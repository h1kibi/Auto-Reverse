"""
Artifact 路径工具 - 按 SHA256 分目录
"""

from pathlib import Path
import hashlib
import re


def compute_sha256(path: str | Path) -> str:
    """计算文件 SHA256"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_filename(name: str) -> str:
    """安全文件名，防止路径穿越"""
    name = Path(name).name
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)


def sample_artifact_dir(base_dir: str | Path, sha256: str) -> Path:
    """样本 artifact 目录: base_dir/<sha_prefix>/<sha256>"""
    return Path(base_dir) / sha256[:2] / sha256


def sample_upload_path(upload_root: str | Path, sha256: str, filename: str) -> Path:
    """样本上传路径: upload_root/<sha_prefix>/<sha256>/filename"""
    return Path(upload_root) / sha256[:2] / sha256 / safe_filename(filename)
