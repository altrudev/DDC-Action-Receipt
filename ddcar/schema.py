"""Strict public wire-schema validation."""
import json
from importlib.resources import files
from jsonschema import Draft202012Validator, FormatChecker

SCHEMA = json.loads(files("ddcar").joinpath("receipt.schema.json").read_text())
DECISION_STATE_SCHEMA = json.loads(
    files("ddcar").joinpath("decision-state.schema.json").read_text()
)
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
DECISION_STATE_VALIDATOR = Draft202012Validator(
    DECISION_STATE_SCHEMA, format_checker=FormatChecker()
)


def validate(obj):
    VALIDATOR.validate(obj)


def validate_decision_state(obj):
    DECISION_STATE_VALIDATOR.validate(obj)
