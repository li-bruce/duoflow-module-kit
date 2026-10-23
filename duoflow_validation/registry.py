"""Static capability checks; supplier code is never imported."""
from pathlib import Path
import re
from jsonschema import Draft202012Validator
from .errors import PlatformError, require
from .workspace_contract import ROLE_IDS
RENDERERS = [
    "text-result",
    "resource",
    "task",
    "form",
    "model-settings",
    "remote-services",
    "module-management",
    "module-page",
    "history",
    "json",
    "workspace",
    "agent-flow",
    "interaction",
    "workflow",
]

class Registry:
    def __init__(self, root: Path):
        self.root = root
        self.modules: list[dict] = []
        self.capabilities: dict[str, dict] = {}
        self.handlers: dict[str, object] = {}
        self.workflow_adapter_factories: dict[str, object] = {}
        self.availability = None
        self.access_allowed = None

    def register(self, module: dict, spec: dict, handler):
        """登记能力和处理器；校验输入输出及两端呈现，暂不执行任何业务。"""
        spec = {**spec, "module_id": module["id"]}
        require(
            bool(re.fullmatch(r"[a-z][a-z0-9_.-]{2,120}", spec["id"])),
            "manifest_id",
            "能力标识格式错误。",
        )
        require(spec["id"] not in self.capabilities, "manifest_duplicate", "能力标识重复。")
        require(spec.get("kind") in ("query", "command"), "manifest_kind", "能力类型错误。")
        require(
            spec.get("execution", {}).get("mode") in ("sync", "background"),
            "manifest_execution",
            "能力执行方式错误。",
        )
        require(
            set(spec.get("roles", [])) <= set(ROLE_IDS) and bool(spec.get("roles")),
            "manifest_roles",
            "能力未声明有效权限。",
        )
        for host in ("page", "conversation"):
            require(
                spec.get("presentation", {}).get(host, {}).get("renderer") in RENDERERS,
                "manifest_presentation",
                "能力需要同时声明页面和对话呈现器。",
            )
        for key in ("input_schema", "output_schema"):
            schema = spec[key]
            Draft202012Validator.check_schema(schema)
            self._check_refs(schema)
        self.capabilities[spec["id"]] = spec
        self.handlers[spec["id"]] = handler

    @staticmethod
    def _check_refs(value):
        if isinstance(value, dict):
            if "$ref" in value:
                require(
                    str(value["$ref"]).startswith("#"),
                    "manifest_schema",
                    "第一版 Schema 仅支持包内展开或本地片段引用。",
                )
            for child in value.values():
                Registry._check_refs(child)
        elif isinstance(value, list):
            for child in value:
                Registry._check_refs(child)

    def validate(self, schema: dict, value: dict):
        """按公开 Schema 检查输入输出；错误只返回字段位置和规则名称。"""
        errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda e: str(e.path))
        if errors:
            # Do not echo input values, potentially credentials, into error text.
            details = [
                {"path": ".".join(map(str, e.path)), "rule": e.validator} for e in errors[:15]
            ]
            raise PlatformError(
                "schema_validation", "输入或输出不符合模块契约，请检查字段。", 422, details
            )
