from enrichment.entities import Entity, EntityType, Finding
from enrichment.storage import merge_findings_into_person


def f(t, v, conf, module, parent):
    return Finding(entity=Entity(t, v), confidence=conf).stamped(module=module, parent=parent)


def test_corroboration_boosts_confidence_capped():
    seed = Entity(EntityType.USERNAME, "janedoe")
    p = seed
    findings = [
        f(EntityType.EMAIL, "jane@x.com", 0.6, "github", p),
        f(EntityType.EMAIL, "jane@x.com", 0.6, "gravatar", p),  # independent agreement
    ]
    prof = merge_findings_into_person(seed, findings).to_dict()
    emails = prof["attributes"]["emails"]
    assert emails[0]["value"] == "jane@x.com"
    # 1 - (1-.6)(1-.6) = 0.84, higher than either source alone, still <= 1
    assert 0.8 < emails[0]["confidence"] <= 1.0


def test_scalar_keeps_highest_confidence_name():
    seed = Entity(EntityType.USERNAME, "janedoe")
    findings = [
        f(EntityType.FULL_NAME, "J Doe", 0.5, "a", seed),
        f(EntityType.FULL_NAME, "Jane Doe", 0.7, "b", seed),
    ]
    prof = merge_findings_into_person(seed, findings).to_dict()
    assert prof["attributes"]["full_name"]["value"] == "Jane Doe"


def test_provenance_is_recorded_for_every_value():
    seed = Entity(EntityType.EMAIL, "jane@x.com")
    findings = [f(EntityType.USERNAME, "janedoe", 0.6, "github", seed)]
    prof = merge_findings_into_person(seed, findings).to_dict()
    prov = prof["provenance"]["username:janedoe"]
    assert prov[0]["module"] == "github"
    assert prov[0]["parent"] == "email:jane@x.com"
