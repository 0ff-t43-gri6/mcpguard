def detect(scope, text, context):
    if "launch codes" in text.lower():
        return [{"rule": "plugin.launch_codes", "severity": "critical", "message": "Launch codes mentioned"}]
    return []
