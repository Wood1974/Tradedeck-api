"""Queries against Shield's own schema — never against public.shield_*.

Every table access in the standalone service goes through here so the schema
name is stated once, and so a future reader cannot accidentally reach
TradeDeck's tables by calling `db().table("shield_jobs")`.
"""
from db import db

SCHEMA = "shield"


def table(name):
    return db().schema(SCHEMA).table(name)


def storage():
    return db().storage
