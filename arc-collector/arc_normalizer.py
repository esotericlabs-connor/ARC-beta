def normalize_ms(raw: dict) -> dict:
    # map signIn / riskyUser to unified schema
    # hash userPrincipalName, extract ipAddress → geo/asn via your existing IP routine
    return {
      "id": raw.get("id"),
      "source": "microsoft",
      "domain": "AIDA",
      "timestamp": raw.get("createdDateTime") or raw.get("riskLastUpdatedDateTime"),
      "identity": { "user_hash": hash_user(raw.get("userPrincipalName")), "geo": geo(raw.get("ipAddress")).cc, "asn": geo(raw.get("ipAddress")).asn },
      "signals": { "auth_confidence": ms_confidence(raw), "geo_risk": ms_geo_risk(raw), "session_anomaly": ms_session(raw) },
      "raw": {"type": raw.get("@odata.type")}
    }

def normalize_google(raw: dict) -> dict:
    # map Admin Reports "login" events
    actor_email = raw.get("actor", {}).get("email")
    ip = pick_param(raw, "ipAddress")
    return {
      "id": raw.get("id", {}).get("time") + ":" + actor_email,
      "source": "google",
      "domain": "AIDA",
      "timestamp": raw.get("id", {}).get("time"),
      "identity": { "user_hash": hash_user(actor_email), "geo": geo(ip).cc if ip else None, "asn": geo(ip).asn if ip else None },
      "signals": { "auth_confidence": google_confidence(raw), "geo_risk": google_geo_risk(raw), "session_anomaly": google_session(raw) },
      "raw": {"app": raw.get("id", {}).get("applicationName")}
    }

def compute_ati(ev: dict) -> int:
    # simple placeholder: identity-weighted ATI
    base = ev["signals"].get("auth_confidence", 50)
    penalty = 20 if ev["signals"].get("session_anomaly") else 0
    return max(0, min(100, base - penalty))