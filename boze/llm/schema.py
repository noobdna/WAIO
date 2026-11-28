"""boze/llm/schema.py -- minimal JSON Schema subset validator (stdlib only).

Supported keywords: type, properties, required, additionalProperties
(false only), enum, minLength, maxLength, minimum, maximum, items,
maxItems. Anything else in a schema raises SchemaError, so a schema
never silently validates less than its author meant.
"""

SUPPORTED = {"type", "properties", "required", "additionalProperties", "enum",
             "minLength", "maxLength", "minimum", "maximum", "items", "maxItems",
             "description"}

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


class SchemaError(Exception):
    """The schema itself uses something this validator does not support."""


def validate(value, schema, path="$"):
    """Return a list of error strings (empty when valid)."""
    if not isinstance(schema, dict):
        raise SchemaError("%s: schema must be an object" % path)
    unknown = set(schema) - SUPPORTED
    if unknown:
        raise SchemaError("%s: unsupported keywords %s" % (path, sorted(unknown)))
    errors = []
    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        for name in types:
            if name not in _TYPES:
                raise SchemaError("%s: unknown type %r" % (path, name))
        if not any(_TYPES[name](value) for name in types):
            return ["%s: expected %s" % (path, "/".join(types))]
    if "enum" in schema and value not in schema["enum"]:
        errors.append("%s: not one of %r" % (path, schema["enum"]))
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append("%s: shorter than %d" % (path, schema["minLength"]))
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append("%s: longer than %d" % (path, schema["maxLength"]))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append("%s: below %r" % (path, schema["minimum"]))
        if "maximum" in schema and value > schema["maximum"]:
            errors.append("%s: above %r" % (path, schema["maximum"]))
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append("%s: missing %r" % (path, key))
        ap = schema.get("additionalProperties", True)
        if ap is not True and ap is not False:
            raise SchemaError("%s: additionalProperties must be true/false" % path)
        for key, sub in value.items():
            if key in props:
                errors.extend(validate(sub, props[key], "%s.%s" % (path, key)))
            elif ap is False:
                errors.append("%s: unexpected key %r" % (path, key))
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append("%s: more than %d items" % (path, schema["maxItems"]))
        if "items" in schema:
            for i, item in enumerate(value):
                errors.extend(validate(item, schema["items"], "%s[%d]" % (path, i)))
    return errors
