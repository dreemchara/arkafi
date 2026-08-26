from flask import redirect

def register_captive_routes(app, portal_url):
    
    CAPTIVE_REDIRECTS = [
        # Apple
        '/hotspot-detect.html', '/captive.html',
        '/library/test/success.html', '/ch',
        # Android
        '/generate_204', '/gen_204',
        '/connectivitycheck.android.com', '/connectivitycheck.gstatic.com',
        '/connectivitycheck.js', '/clients3.google.com',
        '/clients4.google.com', '/android.clients.google.com',
        # Firefox
        '/canonical.html',
        # Linux
        '/check_network_status.txt', '/check.txt',
        '/status.html', '/online.html',
        # Generic
        '/portal', '/portal/', '/index.html', '/wifi/', '/wifi',
        '/isatap', '/wpad.dat', '/redirect', '/redirect.txt',
        '/captiveportal/generate_204', '/cloudflareportal.com',
        '/wifistub.html', '/success.html', '/success.txt',
    ]

    for path in CAPTIVE_REDIRECTS:
        endpoint = f'captive_{path.replace("/", "_")}'
        app.add_url_rule(path, endpoint, lambda: redirect(portal_url))

    @app.route('/connecttest.txt')
    @app.route('/ncsi.txt')
    @app.route('/connecttest.html')
    def windows_probe():
        return "Microsoft Connect Test\n", 200