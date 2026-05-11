def get_recommendations(attack_type: str):
    attack_type = attack_type.lower()

    advice = {
        "dos": {
            "message": "⚠️ DoS Attack Detected — Stay calm, follow these steps:",
            "steps": [
                "Temporarily disconnect from the network.",
                "Block suspicious IPs in your firewall.",
                "Close unused open ports.",
                "Restart your network adapter.",
            ],
        },
        "port_scan": {
            "message": "🔍 Port Scan Detected — Let's secure your ports:",
            "steps": [
                "Close all unnecessary open ports.",
                "Enable strict firewall rules.",
                "Monitor incoming connections for unusual patterns.",
                "Ensure router firewall is enabled.",
            ],
        },
        "sql_injection": {
            "message": "💉 SQL Injection Detected — Protect your database:",
            "steps": [
                "Block the source IP immediately.",
                "Review and patch vulnerable endpoints.",
                "Enable parameterized queries in your app.",
                "Audit database access logs.",
            ],
        },
        "xss": {
            "message": "🌐 XSS Attack Detected — Secure your web layer:",
            "steps": [
                "Enable Content Security Policy (CSP) headers.",
                "Sanitize all user inputs server-side.",
                "Block the source IP in your WAF.",
                "Review recent web application logs.",
            ],
        },
        "malware": {
            "message": "🦠 Malware Activity Detected — Act fast:",
            "steps": [
                "Terminate unknown or suspicious processes.",
                "Disconnect from the internet temporarily.",
                "Run an offline antivirus scan.",
                "Delete temporary files and check startup programs.",
            ],
        },
    }

    return advice.get(attack_type, {
        "message": "✅ Normal Traffic — Everything looks fine.",
        "steps": [
            "Network activity is within normal parameters.",
            "Continue normal operations 😊",
            "System is being monitored in real-time.",
        ],
    })
