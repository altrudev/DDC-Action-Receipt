"""Strict public wire-schema validation."""
import json
from importlib.resources import files
from jsonschema import Draft202012Validator, FormatChecker
SCHEMA=json.loads(files('ddcar').joinpath('receipt.schema.json').read_text())
VALIDATOR=Draft202012Validator(SCHEMA,format_checker=FormatChecker())
def validate(obj):
    VALIDATOR.validate(obj)
