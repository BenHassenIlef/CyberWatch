from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def serialize_doc(doc: dict) -> dict:
    if doc is None:
        return doc
    doc = dict(doc)
    if "_id" in doc:
        doc["id"] = str(doc.pop("_id"))
    for key, value in list(doc.items()):
        if key.endswith("_id") and value is not None:
            doc[key] = str(value)
    return doc
