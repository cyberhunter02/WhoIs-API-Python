from flask import Flask, request, jsonify
import whois
import datetime

app = Flask(__name__)

def to_text(value):
    if value is None:
        return "Not Available"
    if isinstance(value, list):
        return ", ".join([str(v) for v in value if v])
    return str(value)

@app.route("/url", methods=["GET"])
def whois_lookup():
    domain = request.args.get("url")

    if not domain:
        return jsonify({
            "brand": "Cyber Hunter Warrior - COPS",
            "status": "ERROR",
            "message": "URL parameter missing. Use /url?url=example.com"
        })

    try:
        w = whois.whois(domain)
    except Exception as e:
        return jsonify({
            "brand": "Cyber Hunter Warrior - COPS",
            "status": "FAILED",
            "error": str(e)
        })

    response = {
        "brand": "Cyber Hunter Warrior - COPS",
        "tool_name": "WHOIS Intelligence API",
        "tool_type": "OSINT / Domain Intelligence",
        "version": "1.1",
        "result_format": "JSON_STRING_ONLY",
        "timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",

        "input_domain": domain.lower(),
        "top_level_domain": "." + domain.split(".")[-1],

        "domain_name": to_text(w.domain_name),
        "domain_status": to_text(w.status),
        "dnssec_status": to_text(w.dnssec),

        "registrar_name": to_text(w.registrar),
        "registrar_whois_server": to_text(w.whois_server),

        "registration_created_on": to_text(w.creation_date),
        "registration_last_updated_on": to_text(w.updated_date),
        "registration_expiry_on": to_text(w.expiration_date),

        "registrant_organization": to_text(w.org),
        "registrant_name": to_text(w.name),
        "registrant_country": to_text(w.country),
        "registrant_state": to_text(w.state),
        "registrant_city": to_text(w.city),
        "registrant_email_status": "Hidden / Privacy Protected",

        "admin_contact": "Redacted by Registry",
        "technical_contact": "Redacted by Registry",

        "name_servers": to_text(w.name_servers),

        "privacy_status": "Enabled (GDPR Compliant)",
        "data_source": "python-whois library",
        "confidence_note": "WHOIS information may be incomplete or obfuscated",
        "legal_notice": "This data is provided for educational and OSINT purposes only"
    }

    return jsonify(response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
