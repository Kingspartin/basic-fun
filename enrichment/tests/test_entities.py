from enrichment.entities import Entity, EntityType, normalize


def test_email_gmail_dots_and_tags_folded():
    a = Entity(EntityType.EMAIL, "Jane.Doe+shop@GMAIL.com")
    b = Entity(EntityType.EMAIL, "janedoe@gmail.com")
    assert a.normalized == "janedoe@gmail.com"
    assert a.key == b.key


def test_email_non_gmail_keeps_dots_drops_tag():
    e = Entity(EntityType.EMAIL, "Jane.Doe+x@Example.COM")
    assert e.normalized == "jane.doe@example.com"


def test_domain_strips_scheme_www_path():
    assert normalize(EntityType.DOMAIN, "https://WWW.Example.com/path?q=1") == "example.com"


def test_phone_nanp_plus_one_equivalent():
    a = Entity(EntityType.PHONE, "+1 (206) 555-0142")
    b = Entity(EntityType.PHONE, "206-555-0142")
    assert a.normalized == b.normalized == "2065550142"


def test_username_and_account_normalization():
    assert normalize(EntityType.USERNAME, "@JaneDoe") == "janedoe"
    assert normalize(EntityType.ACCOUNT, "Twitter: @Jane") == "twitter:jane"


def test_key_is_type_scoped():
    assert Entity(EntityType.USERNAME, "x").key != Entity(EntityType.DOMAIN, "x").key
