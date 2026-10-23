"""Manifest validation only; no network or credential storage."""
import copy
import re
from jsonschema import Draft202012Validator, SchemaError
from .module_contract import normalize_surfaces
from .workspace_contract import ROLE_IDS
class RemoteServiceError(Exception):
    """Safe public error; no response bodies, URLs, inputs or tokens in messages."""

    def __init__(self, code: str, message: str):
        self.code, self.message = code, message
        super().__init__(message)

class RemoteServiceManager:
    @staticmethod
    def _validate_manifest(manifest):
        def invalid():
            raise RemoteServiceError(
                "remote_invalid_manifest",
                "远程服务清单不符合平台支持的 Manifest 1.0/1.1/1.2 契约，请检查版本、字段、Schema 与双端呈现声明。",
            )

        def fields(obj, required, optional=()):
            if (
                not isinstance(obj, dict)
                or set(required) - set(obj)
                or set(obj) - set(required) - set(optional)
            ):
                invalid()

        def string(value, limit=200, empty=False):
            if (
                not isinstance(value, str)
                or len(value) > limit
                or (not empty and not value.strip())
                or any(ord(c) < 32 for c in value)
            ):
                invalid()

        def identifier(value):
            if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{2,120}", value):
                invalid()

        visited = 0

        def refs(node, depth=0):
            nonlocal visited
            visited += 1
            if depth > 40 or visited > 20000:
                invalid()
            if isinstance(node, dict):
                for key in ("$ref", "$dynamicRef", "$recursiveRef"):
                    if key in node and (
                        not isinstance(node[key], str) or not node[key].startswith("#")
                    ):
                        invalid()
                for child in node.values():
                    refs(child, depth + 1)
            elif isinstance(node, list):
                for child in node:
                    refs(child, depth + 1)

        try:
            fields(manifest, {"protocol_version", "module", "capabilities"}, {"surfaces"})
            if manifest["protocol_version"] not in {"1.0", "1.1", "1.2"}:
                invalid()
            modern = manifest["protocol_version"] == "1.2"
            if manifest["protocol_version"] in {"1.1", "1.2"} and manifest.get("surfaces") is None:
                invalid()
            module = manifest["module"]
            fields(module, {"id", "version", "name", "description"})
            identifier(module["id"])
            string(module["version"], 40)
            string(module["name"], 120)
            string(module["description"], 3000, True)
            capabilities = manifest["capabilities"]
            if not isinstance(capabilities, list) or not 1 <= len(capabilities) <= 64:
                invalid()
            ids = set()
            for cap in capabilities:
                fields(
                    cap,
                    {
                        "id",
                        "version",
                        "title",
                        "description",
                        "kind",
                        "input_schema",
                        "output_schema",
                        "roles",
                        "execution",
                        "presentation",
                    },
                    {"result"},
                )
                identifier(cap["id"])
                if cap["id"] in ids:
                    invalid()
                ids.add(cap["id"])
                string(cap["version"], 40)
                string(cap["title"], 200)
                string(cap["description"], 3000, True)
                if cap["kind"] not in {"query", "command"}:
                    invalid()
                roles = cap["roles"]
                if (
                    not isinstance(roles, list)
                    or not roles
                    or any(
                        role not in (ROLE_IDS if modern else ["admin", "member"]) for role in roles
                    )
                    or len(set(roles)) != len(roles)
                ):
                    invalid()
                fields(cap["execution"], {"mode", "confirmation"})
                if cap["execution"]["mode"] != "background" or not isinstance(
                    cap["execution"]["confirmation"], bool
                ):
                    invalid()
                fields(cap["presentation"], {"page", "conversation"})
                for host in ("page", "conversation"):
                    fields(cap["presentation"][host], {"renderer"})
                    if cap["presentation"][host]["renderer"] not in (
                        {"text-result", "json", "workspace"} if modern else {"text-result", "json"}
                    ):
                        invalid()
                for name in ("input_schema", "output_schema"):
                    schema = cap[name]
                    if not isinstance(schema, dict) or schema.get("type") != "object":
                        invalid()
                    refs(schema)
                    Draft202012Validator.check_schema(schema)
                if "result" in cap:
                    result = cap["result"]
                    fields(
                        result, {"resource_type", "title"}, {"text_artifact", "title_from_input"}
                    )
                    identifier(result["resource_type"])
                    string(result["title"], 200)
                    if "title_from_input" in result:
                        string(result["title_from_input"], 120)
                    if "text_artifact" in result:
                        artifact = result["text_artifact"]
                        fields(artifact, {"field", "name"})
                        string(artifact["field"], 120)
                        string(artifact["name"], 180)
                        if any(c in artifact["name"] for c in "/\\") or artifact["name"] in {
                            ".",
                            "..",
                        }:
                            invalid()
            normalize_surfaces(
                module["id"],
                capabilities,
                manifest.get("surfaces"),
                allow_embedded=True,
                allow_skills=modern,
            )
            # Preserve legacy 1.0 manifests byte-for-field for cached-contract
            # comparison. Registration callers normalize their surfaces as needed.
            # Protocol 1.1 changes discovery only; invoke envelopes remain 1.0.
            return copy.deepcopy(manifest)
        except (SchemaError, TypeError, ValueError, KeyError, RecursionError):
            invalid()
