"""Per-user Windows profiles. API keys are stored by Windows Credential Manager."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import sqlite3

from .local_candidate import _endpoint


class _Credential(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR), ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD), ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR),
    ]


def _vault(operation, profile, key=""):
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    name = "KODA/LocalAI/" + hashlib.sha256(profile.encode()).hexdigest()
    pointer = ctypes.POINTER(_Credential)()
    api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(type(pointer))]
    api.CredWriteW.argtypes = [type(pointer), wintypes.DWORD]
    api.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    api.CredFree.argtypes = [ctypes.c_void_p]
    api.CredFree.restype = None
    if operation == "save":
        raw = key.encode("utf-16-le")
        if len(raw) > 2560:
            raise ValueError("API 키가 너무 깁니다.")
        blob = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        credential = _Credential(Type=1, TargetName=name, CredentialBlobSize=len(raw),
                                 CredentialBlob=blob, Persist=2, UserName="KODA")
        if api.CredWriteW(ctypes.byref(credential), 0):
            return ""
    elif operation == "delete":
        if api.CredDeleteW(name, 1, 0):
            return ""
    elif api.CredReadW(name, 1, 0, ctypes.byref(pointer)):
        try:
            cred = pointer.contents
            return ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize).decode("utf-16-le")
        finally:
            api.CredFree(pointer)
    error = ctypes.get_last_error()
    if error == 1168 and operation != "save":  # ERROR_NOT_FOUND
        return ""
    raise OSError(f"Windows Credential Manager ({error})")


def with_profile(data):
    """Handle profile management or resolve a saved credential for a loopback call."""
    if os.name != "nt":
        return None
    action = data.get("action")
    if action == "inspect":
        return None
    if action in {"models", "propose"}:
        if not data.get("key"):
            base = str(data.get("base", "")).rstrip("/")
            _endpoint(base)
            model = str(data.get("model", "")).strip()
            data["key"] = _vault("read", base + "\0" + model)
        return None
    if action not in {"profiles", "save-profile", "delete-profile"}:
        return None
    directory = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "KODA"
    directory.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(directory / "local-ai.sqlite3")
    try:
        with db:
            db.execute("CREATE TABLE IF NOT EXISTS profiles(base TEXT NOT NULL, model TEXT NOT NULL, PRIMARY KEY(base, model))")
            if action != "profiles":
                base = str(data.get("base", "")).rstrip("/")
                _endpoint(base)
                model, key = str(data.get("model", "")).strip(), str(data.get("key", ""))
                if not 0 < len(model) <= 256:
                    raise ValueError("모델 이름을 입력하세요.")
                profile = base + "\0" + model
                if action == "delete-profile":
                    _vault("delete", profile)
                    db.execute("DELETE FROM profiles WHERE base=? AND model=?", (base, model))
                else:
                    if key:
                        _vault("save", profile, key)
                    db.execute("INSERT OR REPLACE INTO profiles VALUES(?,?)", (base, model))
            return {"profiles": [{"base": b, "model": m} for b, m in db.execute("SELECT * FROM profiles ORDER BY base,model")]}
    finally:
        db.close()
