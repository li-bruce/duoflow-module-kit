"""Access-definition validation, without the authorization database."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator
from .errors import require
DEFINITION_SCHEMA=json.loads((Path(__file__).resolve().parents[1]/'contracts/access/v1/definition.schema.json').read_text(encoding='utf-8'))

def _validate(schema, value):
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda e: str(e.path))
    require(not errors, "access_contract_invalid", "权限契约不符合已注册版本", 422)

def validate_definition(definition):
    _validate(DEFINITION_SCHEMA, definition)
    prefix = definition["module_id"] + "."
    for section in ("permissions", "role_templates", "experiences", "workitem_sources"):
        ids = [item["id"] for item in definition[section]]
        require(len(set(ids)) == len(ids), "access_duplicate_id", "权限定义含重复标识", 422)
        require(
            all(item.startswith(prefix) for item in ids),
            "access_namespace",
            "权限定义不得越过模块命名空间",
            422,
        )
    permissions = {item["id"] for item in definition["permissions"]}
    for role in definition["role_templates"]:
        require(
            set(role["permissions"]) <= permissions,
            "access_unknown_permission",
            "角色引用未声明权限",
            422,
        )
        require(
            set(role["required_scope"]) <= set(definition["scope_keys"]),
            "access_unknown_scope",
            "角色引用未声明范围",
            422,
        )
    seen = set()
    for mapping in definition["command_mappings"]:
        require(
            mapping["capability_id"].startswith(prefix),
            "access_namespace",
            "不能映射其他模块的能力",
            422,
        )
        require(
            mapping["permission"] in permissions,
            "access_unknown_permission",
            "动作引用未声明权限",
            422,
        )
        key = (mapping["capability_id"], mapping.get("command"))
        require(key not in seen, "access_duplicate_mapping", "能力命令映射重复", 422)
        seen.add(key)
    # A catch-all mapping and command mappings on one capability would make an
    # unknown command accidentally inherit the broad catch-all permission.
    for capability, command in seen:
        if command is None:
            require(
                not any(capability == c and cmd is not None for c, cmd in seen),
                "access_ambiguous_mapping",
                "通用能力映射不能和命令映射混合",
                422,
            )
    for experience in definition["experiences"]:
        require(
            set(experience["required_permissions"]) <= permissions,
            "access_unknown_permission",
            "办理视图引用未声明权限",
            422,
        )
    experiences = {item["id"] for item in definition["experiences"]}
    capabilities = {item["capability_id"] for item in definition["command_mappings"]}
    for source in definition["workitem_sources"]:
        require(
            source["experience_id"] in experiences,
            "access_unknown_experience",
            "待办源引用未声明视图",
            422,
        )
        require(
            source["capability_id"] in capabilities,
            "access_unknown_capability",
            "待办源引用未映射能力",
            422,
        )
