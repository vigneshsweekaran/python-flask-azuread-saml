import os
from flask import Flask, request, session, redirect, url_for, render_template
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
import json

app = Flask(__name__)
app.secret_key = os.urandom(24)

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'saml'))
    return auth

def prepare_flask_request(request):
    # If server is behind proxys or balancers, use the HTTP_X_FORWARDED fields
    return {
        'https'         : 'on' if request.scheme == 'https' else 'off',
        'http_host'     : request.host,
        'script_name'   : request.path,
        'get_data'      : request.args.copy(),
        'post_data'     : request.form.copy(),
        # Advanced request options not covered in this example
        'query_string'  : request.query_string
    }

@app.route('/')
def index():
    if 'samlUserdata' in session:
        return render_template('index.html')
    else:
        return render_template('login.html')

@app.route('/login')
def login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())

@app.route('/logout')
def logout():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.logout())

@app.route('/saml/acs', methods=['POST'])
def acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    if not errors:
        session['samlUserdata'] = auth.get_attributes()
        session['samlNameId'] = auth.get_nameid()
        session['samlSessionIndex'] = auth.get_session_index()
        self_url = OneLogin_Saml2_Utils.get_self_url(req)
        if 'RelayState' in request.form and self_url != request.form['RelayState']:
            return redirect(auth.redirect_to(request.form['RelayState']))
        return redirect(url_for('index'))
    else:
        print("Errors found: ", errors)
        return 'Error in SAML response'

@app.route('/saml/metadata')
def metadata():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = app.make_response(metadata)
        resp.headers['Content-Type'] = 'text/xml'
        return resp
    else:
        return 'Error in metadata'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)