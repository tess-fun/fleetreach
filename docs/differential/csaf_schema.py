#!/usr/bin/env python3
"""Check CSAF documents against the CSAF 2.0 JSON schema, with no dependencies.

usage: csaf_schema.py <csaf_json_schema.json> <document.json>...

A small JSON Schema 2020-12 checker for the keywords the CSAF schema uses: type, properties,
required, additionalProperties, items, minItems, uniqueItems, min/maxProperties, minLength,
maxLength, enum, const, pattern, format (date-time, uri), $ref (to its own $defs; the CVSS
schemas it refers to are checked only as objects), oneOf, anyOf, allOf, not, dependentRequired.
An unknown keyword stops the run rather than passing silently. The schema ships in the
gocsaf module (github.com/gocsaf/csaf/v3/csaf/schema) and at docs.oasis-open.org.

The schema is not the whole standard: CSAF's mandatory tests (section 6.1) are not run here.
"""
import json, re, sys
from datetime import datetime

KNOWN = {"$schema", "$id", "$defs", "$ref", "title", "description", "examples", "default",
         "type", "properties", "required", "additionalProperties", "items", "minItems",
         "uniqueItems", "minProperties", "maxProperties", "minLength", "maxLength", "enum", "const", "pattern",
         "format", "oneOf", "anyOf", "allOf", "not", "dependentRequired", "contains"}
TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def is_type(value, kind):
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, TYPES[kind])


def check(schema, value, root, path, errors):
    if schema is True or schema == {}:
        return
    unknown = set(schema) - KNOWN
    if unknown:
        sys.exit(f"unknown schema keywords {sorted(unknown)} at {path}")
    if "$ref" in schema:
        ref = schema["$ref"]
        if ref.startswith("#/"):
            target = root
            for part in ref[2:].split("/"):
                target = target[part]
            check(target, value, root, path, errors)
        elif not isinstance(value, dict):
            errors.append(f"{path}: expected an object for {ref}")
    if "type" in schema:
        kinds = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(is_type(value, k) for k in kinds):
            errors.append(f"{path}: expected {kinds}, got {type(value).__name__}")
            return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in {schema['enum']}")
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: {value!r} is not {schema['const']!r}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: {value!r} does not match {schema['pattern']}")
        fmt = schema.get("format")
        if fmt == "date-time":
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"{path}: {value!r} is not a date-time")
        elif fmt in ("uri", "iri") and not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value):
            errors.append(f"{path}: {value!r} is not a URI")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if schema.get("uniqueItems"):
            seen = [json.dumps(v, sort_keys=True) for v in value]
            if len(seen) != len(set(seen)):
                errors.append(f"{path}: items are not unique")
        if "items" in schema:
            for i, v in enumerate(value):
                check(schema["items"], v, root, f"{path}[{i}]", errors)
    if isinstance(value, dict):
        if len(value) < schema.get("minProperties", 0):
            errors.append(f"{path}: fewer than {schema['minProperties']} properties")
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            errors.append(f"{path}: more than {schema['maxProperties']} properties")
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing {key}")
        props = schema.get("properties", {})
        for key, v in value.items():
            if key in props:
                check(props[key], v, root, f"{path}.{key}", errors)
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected property {key}")
        for key, needs in schema.get("dependentRequired", {}).items():
            if key in value:
                errors.extend(f"{path}: {key} needs {n}" for n in needs if n not in value)
    for keyword in ("allOf", "anyOf", "oneOf"):
        if keyword in schema:
            results = []
            for sub in schema[keyword]:
                sub_errors = []
                check(sub, value, root, path, sub_errors)
                results.append(sub_errors)
            passed = sum(not r for r in results)
            if keyword == "allOf":
                for r in results:
                    errors.extend(r)
            elif keyword == "anyOf" and passed == 0:
                errors.append(f"{path}: matches none of anyOf")
            elif keyword == "oneOf" and passed != 1:
                errors.append(f"{path}: matches {passed} of oneOf, not exactly one")
    if "not" in schema:
        sub_errors = []
        check(schema["not"], value, root, path, sub_errors)
        if not sub_errors:
            errors.append(f"{path}: matches a schema it must not")


def main(schema_path, *docs):
    with open(schema_path) as f:
        schema = json.load(f)
    bad = 0
    for doc in docs:
        try:
            with open(doc) as f:
                value = json.load(f)
        except json.JSONDecodeError as e:
            print(f"{doc}: not JSON ({e})")
            bad += 1
            continue
        errors = []
        check(schema, value, schema, "$", errors)
        print(f"{doc}: {'valid' if not errors else f'{len(errors)} error(s)'}")
        for e in errors[:20]:
            print("  " + e)
        bad += bool(errors)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    main(*sys.argv[1:])
