#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
                        .('
                       /%/\\'
                      (%(%))'
                       curl'

Before you can use curlish you need to register the site with the curlish
client.  For that you can use the --add-site parameter which will walk you
through the process.

example:

  $ curlish https://graph.facebook.com/me

Notes on the authorization_code grant type: curlish spawns an HTTP server
that handles a single request on http://127.0.0.1:62231/ which acts as a
valid redirect target.  If you need the authorization_code grant, let it
redirect there.

common curl options:
  -v                     verbose mode
  -i                     prints the headers
  -X METHOD              specifies the method
  -H "Header: value"     emits a header with a value
  -d "key=value"         emits a pair of form data

curl extension options:
  METHOD                 shortcut for -XMETHOD if it's one of the known
                         HTTP methods.
  -J key=value           transmits a JSON string value.
  -J key:=value          transmits raw JSON data for a key (bool int etc.)
"""
from __future__ import with_statement
import os
import re
import sys
import cgi
import webbrowser
import argparse
try:
    import json
    from json.encoder import JSONEncoder
except ImportError:
    import simplejson as json
    from simplejson.encoder import JSONEncoder
import urllib
import urlparse
import subprocess
import base64
from copy import deepcopy
from httplib import HTTPConnection, HTTPSConnection
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from getpass import getpass
from uuid import UUID


def str_to_uuid(s):
    try:
        UUID(s)
        return s
    except:
        print "%s is not a valid UUID" % s
        sys.exit(1)


KNOWN_HTTP_METHODS = set(['GET', 'POST', 'HEAD', 'PUT', 'OPTIONS',
                          'TRACE', 'DELETE', 'PATCH'])

DEFAULT_SETTINGS = {
    'curl_path': None,
    'http_port': 62231,
    'json_indent': 2,
    'colors': {
        'statusline_ok': 'green',
        'statusline_error': 'red',
        'header': 'teal',
        'brace': 'teal',
        'operator': None,
        'constant': 'blue',
        'number': 'purple',
        'string': 'yellow',
        'objstring': 'green'
    },
    'sites': {
        "facebook": {
            "extra_headers": {},
            "request_token_params": {
                "scope": "email"
            },
            "authorize_url": "https://www.facebook.com/dialog/oauth",
            "base_url": "https://graph.facebook.com/",
            "client_id": "384088028278656",
            "client_secret": "14c75a494cda2e11e8760095ec972915",
            "grant_type": "authorization_code",
            "access_token_url": "/oauth/access_token"
        }
    },
    'token_cache': {}
}
ANSI_CODES = {
    'black': '\x1b[30m',
    'blink': '\x1b[05m',
    'blue': '\x1b[34m',
    'bold': '\x1b[01m',
    'faint': '\x1b[02m',
    'green': '\x1b[32m',
    'purple': '\x1b[35m',
    'red': '\x1b[31m',
    'reset': '\x1b[39;49;00m',
    'standout': '\x1b[03m',
    'teal': '\x1b[36m',
    'underline': '\x1b[04m',
    'white': '\x1b[37m',
    'yellow': '\x1b[33m'
}


_list_marker = object()
_value_marker = object()


def decode_flat_data(pairiter):
    def _split_key(name):
        result = name.split('.')
        for idx, part in enumerate(result):
            if part.isdigit():
                result[idx] = int(part)
        return result

    def _enter_container(container, key):
        if key not in container:
            return container.setdefault(key, {_list_marker: False})
        return container[key]

    def _convert(container):
        if _value_marker in container:
            force_list = False
            values = container.pop(_value_marker)
            if container.pop(_list_marker):
                force_list = True
                values.extend(_convert(x[1]) for x in
                              sorted(container.items()))
            if not force_list and len(values) == 1:
                values = values[0]
            return values
        elif container.pop(_list_marker):
            return [_convert(x[1]) for x in sorted(container.items())]
        return dict((k, _convert(v)) for k, v in container.iteritems())

    result = {_list_marker: False}
    for key, value in pairiter:
        parts = _split_key(key)
        if not parts:
            continue
        container = result
        for part in parts:
            last_container = container
            container = _enter_container(container, part)
            last_container[_list_marker] = isinstance(part, (int, long))
        container[_value_marker] = [value]

    return _convert(result)


def get_color(element):
    user_colors = settings.values['colors']
    name = user_colors.get(element)
    if name is None and element not in user_colors:
        name = DEFAULT_SETTINGS['colors'].get(element)
    if name is not None:
        return ANSI_CODES.get(name, '')
    return ''


def isatty():
    """Is stdout connected to a terminal or a file?"""
    if not hasattr(sys.stdout, 'isatty'):
        return False
    if not sys.stdout.isatty():
        return False
    return True


def is_color_terminal():
    """Returns `True` if this terminal has colors."""
    if not isatty():
        return False
    if 'COLORTERM' in os.environ:
        return True
    term = os.environ.get('TERM', 'dumb').lower()
    if term in ('xterm', 'linux') or 'color' in term:
        return True
    return False


def fail(message):
    """Fails with an error message."""
    print >> sys.stderr, 'error:', message
    sys.exit(1)


def find_url_arg(arguments):
    """Finds the URL argument in a curl argument list."""
    for idx, arg in enumerate(arguments):
        if arg.startswith(('http:', 'https:')):
            return idx


class AuthorizationHandler(BaseHTTPRequestHandler):
    """Callback handler for the code based authorization"""

    def do_GET(self):
        self.send_response(200, 'OK')
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.server.token_response = dict((k, v[-1]) for k, v in
            cgi.parse_qs(self.path.split('?')[-1]).iteritems())
        if 'code' in self.server.token_response:
            title = 'Tokens Received'
            text = 'The tokens were transmitted successfully to curlish.'
        else:
            title = 'Error on Token Exchange'
            text = 'Could not exchange tokens :-('
        self.wfile.write('''
            <!doctype html>
            <title>%(title)s</title>
            <style type=text/css>
                body { font-family: sans-serif; margin: 60px auto; width: 400px; }
                h1   { font-weight: normal; size: 28px; color: #b00; margin: 0 0 15px 0; }
                p    { margin: 7px 0 0 20px; }
            </style>
            <h1>%(title)s</h1>
            <p>%(text)s
            <p>You can now close this window, it's no longer needed.
        ''' % locals())
        self.wfile.close()

    def log_message(self, *args, **kwargs):
        pass


class Settings(object):
    """Wrapper around the settings file"""

    def __init__(self):
        if os.name == 'nt':
            self.filename = os.path.expandvars(r'%APPDATA%\\FireteamCurlish\\config.json')
        else:
            self.filename = os.path.expanduser(r'~/.ftcurlish.json')

        rv = deepcopy(DEFAULT_SETTINGS)
        if os.path.isfile(self.filename):
            with open(self.filename) as f:
                try:
                    rv.update(json.load(f))
                except Exception:
                    pass
        if not rv['curl_path']:
            rv['curl_path'] = get_default_curl_path()
        self.values = rv

    def save(self):
        dirname = os.path.dirname(self.filename)
        try:
            os.makedirs(dirname)
        except OSError:
            pass
        with open(self.filename, 'w') as f:
            json.dump(self.values, f, indent=2)


class Site(object):
    """Represents a single site."""

    def __init__(self, name, values):
        def _full_url(url):
            if self.base_url is not None:
                return urlparse.urljoin(self.base_url, url)
            return url
        self.name = name
        self.base_url = values.get('base_url')
        self.grant_type = values.get('grant_type', 'authorization_code')
        self.access_token_url = _full_url(values.get('access_token_url'))
        self.authorize_url = _full_url(values.get('authorize_url'))
        self.client_id = values.get('client_id')
        self.client_secret = values.get('client_secret')
        self.request_token_params = values.get('request_token_params') or {}
        self.extra_headers = values.get('extra_headers') or {}
        self.bearer_transmission = values.get('bearer_transmission', 'query')
        self.access_token = None

    def make_request(self, method, url, headers=None, data=None):
        """Makes an HTTP request to the site."""
        u = urlparse.urlparse(url)
        pieces = u.netloc.rsplit(':', 1)
        secure = u.scheme == 'https'
        host = pieces[0].strip('[]')
        if len(pieces) == 2 and pieces[-1].isdigit():
            port = int(pieces[-1])
        else:
            port = secure and 443 or 80
        conncls = secure and HTTPSConnection or HTTPConnection
        conn = conncls(host, port)
        if isinstance(data, dict):
            data = urllib.urlencode(data)

        real_headers = self.extra_headers.copy()
        real_headers.update(headers or ())

        conn.request(method, u.path, data, real_headers)
        resp = conn.getresponse()

        ct = resp.getheader('Content-Type')
        if ct.startswith('application/json') or ct.startswith('text/javascript'):
            resp_data = json.loads(resp.read())
        elif ct.startswith('text/html'):
            fail('Invalid response from server: ' + resp.read())
        else:
            resp_data = dict((k, v[-1]) for k, v in
                cgi.parse_qs(resp.read()).iteritems())

        return resp.status, resp_data

    def get_access_token(self, params):
        """Tries to load tokens with the given parameters."""
        data = params.copy()

        # Provide the credentials both as a basic authorization header as well as
        # the parameters in the URL.  Should make everybody happy.  At least I hope so.
        data['client_id'] = self.client_id
        data['client_secret'] = self.client_secret
        creds = self.client_id + ':' + self.client_secret
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
                   'Authorization': 'Basic ' + base64.b64encode(creds)}

        status, data = self.make_request('POST',
                                         self.access_token_url, data=data, headers=headers)
        if status == 200:
            return data['access_token']
        error = data.get('error')
        if error in ('invalid_grant', 'access_denied'):
            return None
        error_msg = data.get('error_description')
        fail("Couldn't authorize: %s - %s" % (error, error_msg))

    def request_password_grant(self):
        while 1:
            params = {'grant_type': 'password'}
            params['username'] = raw_input('Username: ')
            params['password'] = getpass()
            params.update(self.request_token_params)
            rv = self.get_access_token(params)
            if rv is None:
                print 'Error: invalid credentials'
                continue
            settings.values['token_cache'][self.name] = rv
            return

    def request_authorization_code_grant(self):
        redirect_uri = 'http://127.0.0.1:%d/' % settings.values['http_port']
        params = {
            'client_id':        self.client_id,
            'redirect_uri':     redirect_uri,
            'response_type':    'code'
        }
        params.update(self.request_token_params)
        browser_url = '%s?%s' % (
            self.authorize_url,
            urllib.urlencode(params)
        )
        webbrowser.open(browser_url)
        server_address = ('127.0.0.1', settings.values['http_port'])
        httpd = HTTPServer(server_address, AuthorizationHandler)
        httpd.token_response = None
        httpd.handle_request()
        if 'code' in httpd.token_response:
            return self.exchange_code_for_token(httpd.token_response['code'],
                                                redirect_uri)
        print 'Could not sign in: grant cancelled'
        for key, value in httpd.token_response.iteritems():
            print '  %s: %s' % (key, value)
        sys.exit(1)

    def exchange_code_for_token(self, code, redirect_uri):
        settings.values['token_cache'][self.name] = self.get_access_token({
            'code':         code,
            'grant_type':   'authorization_code',
            'redirect_uri': redirect_uri
        })

    def request_tokens(self):
        if self.grant_type == 'password':
            self.request_password_grant()
        elif self.grant_type == 'authorization_code':
            self.request_authorization_code_grant()
        else:
            fail('Invalid grant configured: %s' % self.grant_type)

    def fetch_token_if_necessarys(self):
        token_cache = settings.values['token_cache']
        if token_cache.get(self.name) is None:
            self.request_tokens()
        self.access_token = token_cache[self.name]


def get_site_by_name(name):
    """Finds a site by its name."""
    rv = settings.values['sites'].get(name)
    if rv is not None:
        return Site(name, rv)


def get_site(site_name, url_arg):
    """Tries to look up a site from the config or automatically."""
    if site_name is not None:
        site = get_site_by_name(site_name)
        if site is not None:
            return site
        fail('Site %s does not exist' % site_name)

    matches = []
    for name, site in settings.values['sites'].iteritems():
        base_url = site.get('base_url')
        if base_url and url_arg.startswith(base_url):
            matches.append(Site(name, site))
            break
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        fail('Too many matches.  Please specificy an application '
             'explicitly')


def get_default_curl_path():
    """Tries to find curl and returns the path to it."""
    def tryrun(path):
        subprocess.call([path, '--version'], stdout=subprocess.PIPE,
                        stdin=subprocess.PIPE)
        return True
    if tryrun('curl'):
        return 'curl'
    base = os.path.abspath(os.path.dirname(__file__))
    for name in 'curl', 'curl.exe':
        fullpath = os.path.join(base, name)
        if tryrun(fullpath):
            return fullpath


def colorize_json_stream(iterator):
    """Adds colors to a JSON event stream."""
    for event in iterator:
        color = None
        e = event.strip()
        if e in '[]{}':
            color = get_color('brace')
        elif e in ',:':
            color = get_color('operator')
        elif e[:1] == '"':
            color = get_color('string')
        elif e in ('true', 'false', 'null'):
            color = get_color('constant')
        else:
            color = get_color('number')
        if color is not None:
            event = color + event + ANSI_CODES['reset']
        yield event


def print_formatted_json(json_data):
    """Reindents JSON and colorizes if wanted.  We use our own wrapper
    around json.dumps because we want to inject colors and the simplejson
    iterator encoder does some buffering between separate events that makes
    it really hard to inject colors.
    """
    if is_color_terminal():
        def colorize(colorname, text):
            color = get_color(colorname)
            reset = ANSI_CODES['reset']
            return color + text + reset
    else:
        colorlize = lambda x: x

    def _walk(obj, indentation, inline=False, w=sys.stdout.write):
        i = ' ' * (indentation * settings.values['json_indent'])
        if not inline:
            w(i)
        if isinstance(obj, basestring):
            w(colorize('string', json.dumps(obj)))
        elif isinstance(obj, (int, long, float)):
            w(colorize('number', json.dumps(obj)))
        elif obj in (True, False, None):
            w(colorize('constant', json.dumps(obj)))
        elif isinstance(obj, list):
            if not obj:
                w(colorize('brace', '[]'))
            else:
                w(colorize('brace', '[\n'))
                for idx, item in enumerate(obj):
                    if idx:
                        w(colorize('operator', ',\n'))
                    _walk(item, indentation + 1)
                w(colorize('brace', '\n' + i + ']'))
        elif isinstance(obj, dict):
            if not obj:
                w(colorize('brace', '{}'))
            else:
                w(colorize('brace', '{\n'))
                for idx, (key, value) in enumerate(obj.iteritems()):
                    if idx:
                        w(colorize('operator', ',\n'))
                    ki = i + ' ' * settings.values['json_indent']
                    w(ki + colorize('objstring', json.dumps(key)))
                    w(colorize('operator', ': '))
                    _walk(value, indentation + 1, inline=True)
                w(i + colorize('brace', '\n' + i + '}'))
        else:
            # hmm. should not happen, but let's just assume it might
            # because of json changes
            w(json.dumps(obj))


    _walk(json_data, 0)
    sys.stdout.write('\n')
    sys.stdout.flush()


def beautify_curl_output(iterable, hide_headers):
    """Parses curl output and adds colors and reindents as necessary."""
    json_body = False
    has_colors = is_color_terminal()

    # Headers
    for line in iterable:
        if has_colors and re.search(r'^HTTP/', line):
            if re.search('HTTP/\d+.\d+ [45]\d+', line):
                color = get_color('statusline_error')
            else:
                color = get_color('statusline_ok')
            sys.stdout.write(color + line + ANSI_CODES['reset'])
            continue
        if re.search(r'^Content-Type:\s*(text/javascript|application/(.+?\+)?json)\s*(?i)', line):
            json_body = True
        if not hide_headers:
            # Nicer headers if we detect them
            if not line.startswith(' ') and ':' in line:
                key, value = line.split(':', 1)
            else:
                key = None
            if has_colors and key is not None:
                sys.stdout.write(get_color('header') + key + ANSI_CODES['reset']
                    + ': ' + value.lstrip())
            else:
                sys.stdout.write(line)
            sys.stdout.flush()
        if line == '\r\n':
            break

    # JSON Body.  Do not reindent if we have headers and are piping
    # into a file because of changing content length.
    if json_body and (hide_headers or isatty()):
        data = json.loads(''.join(iterable))
        print_formatted_json(data)

    # Regular body
    else:
        for line in iterable:
            sys.stdout.write(line)
            sys.stdout.flush()


def clear_token_cache(site_name):
    """Delets all tokens or the token of a site."""
    site = None
    if site_name is not None:
        site = get_site_by_name(site_name)
        if site is None:
            fail('Site %s does not exist' % site_name)
    if site is None:
        settings.values['token_cache'] = {}
        print 'Cleared the token cache'
    else:
        settings.values['token_cache'].pop(site.name, None)
        print 'Cleared the token cache for %s' % site.name
    settings.save()


def add_site(site_name):
    """Registers a new site with the config."""
    def prompt(prompt, one_of=None, default=None):
        if default is not None:
            prompt += ' [%s]' % default
        if one_of:
            prompt += ' (options=%s)' % ', '.join(sorted(one_of))
        while 1:
            value = raw_input(prompt + ': ')
            if value:
                if one_of and value not in one_of:
                    print 'error: invalid value'
                    continue
                return value
            if default is not None:
                return default

    base_url = prompt('base_url')
    if prompt('Configure OAuth 2.0?', ['yes', 'no'], 'yes') == 'yes':
        grant_type = prompt('grant_type',
            one_of=['password', 'authorization_code'],
            default='authorization_code')
        access_token_url = prompt('access_token_url')
        if grant_type == 'authorization_code':
            authorize_url = prompt('authorize_url')
        client_id = prompt('client_id')
        client_secret = prompt('client_secret')
        bearer_transmission = prompt('bearer_transmission',
            one_of=['header', 'query'], default='query')
    else:
        grant_type = None
        access_token_url = None
        client_id = None
        client_secret = None
        bearer_transmission = None

    settings.values['sites'][site_name] = {
        'extra_headers': {},
        'request_token_params': {},
        'base_url': base_url,
        'grant_type': grant_type,
        'base_url': base_url,
        'access_token_url': access_token_url,
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': grant_type,
        'bearer_transmission': bearer_transmission
    }
    settings.values['token_cache'].pop(site_name, None)
    settings.save()
    print 'Site %s added' % site_name


def remove_site(site_name):
    """Removes a site from the config."""
    try:
        settings.values['sites'].pop(site_name)
    except KeyError:
        fail('Site %s does not exist' % site_name)
    settings.save()
    print 'Site %s removed' % site_name


def list_sites():
    """Prints a list of all sites."""
    print 'Registered sites:'
    print
    for name, site in sorted(settings.values['sites'].items()):
        print '  %s' % name
        for key, value in sorted(site.items()):
            if isinstance(value, dict):
                print '    %s:%s' % (key, not value and ' -' or '')
                for key, value in sorted(value.items()):
                    print '      %s: %s' % (key, value)
            else:
                print '    %s: %s' % (key, value)
        print


def add_content_type_if_missing(args, content_type):
    """Very basic hack that adds a content type if no content type
    was mentioned so far.
    """
    was_h = False
    for arg in args:
        iarg = arg.lower()
        if iarg.startswith('-hcontent-type'):
            return
        elif iarg == '-h':
            was_h = True
        elif was_h:
            if iarg.startswith('content-type'):
                return
            was_h = False
    args.append('-H')
    args.append('Content-Type: ' + content_type)


def handle_curlish_arguments(args):
    new_args = []
    json_pairs = []

    argiter = iter(args)
    def _get_next_arg(error):
        try:
            return argiter.next()
        except StopIteration:
            fail('Error: ' + error)

    def handle_json_value(value):
        if ':=' in value:
            dkey, value = value.split(':=', 1)
            try:
                value = json.loads(value)
            except Exception:
                fail('Error: invalid JSON data for "%s"' % dkey)
        elif '=' in value:
            dkey, value = value.split('=', 1)
            vlaue = json.dumps(value)
        else:
            fail('Error: malformed json data with -J')
        json_pairs.append((dkey, value))

    for idx, arg in enumerate(argiter):
        # Automatic -X in front of known http method names
        if arg in KNOWN_HTTP_METHODS:
            new_args.append('-X' + arg)
        elif arg == '-J':
            handle_json_value(_get_next_arg('-J requires an argument'))
        elif arg.startswith('-J'):
            handle_json_value(arg[2:])
        # Regular argument
        else:
            new_args.append(arg)

    json_data = decode_flat_data(json_pairs)
    need_json = bool(json_data)
    if len(json_data) == 1 and '' in json_data:
        json_data = json_data['']

    if need_json:
        add_content_type_if_missing(new_args, 'application/json')
        new_args.append('--data-binary')
        new_args.append(json.dumps(json_data))

    return new_args


def invoke_curl(site, curl_path, args, url_arg):
    if args[0] == '--':
        args.pop(0)

    if not curl_path:
        fail('Could not find curl.  Put it into your config')

    url = args[url_arg]
    if site is not None and site.bearer_transmission is not None:
        if site.bearer_transmission == 'header':
            args += ['-H', 'Authorization: Bearer %s' % site.access_token]
        elif site.bearer_transmission == 'query':
            url += ('?' in url and '&' or '?') + 'access_token=' + \
                urllib.quote(site.access_token)
        else:
            fail('Bearer transmission %s is unknown.' % site.bearer_transmission)

    args[url_arg] = url

    if site is not None:
        for key, value in site.extra_headers.iteritems():
            args += ['-H', '%s: %s' % (key, value)]

    # Force response headers
    hide_headers = False
    if not any(arg == '-i' or (arg[:1] == '-' and \
               arg[1:2] != '-' and 'i' in arg) for arg in args):
        args.append('-i')
        hide_headers = True

    # Hide stats
    args.append('-s')

    # Handle curlish specific argument shortcuts
    args = handle_curlish_arguments(args)

    p = subprocess.Popen([curl_path] + args, stdout=subprocess.PIPE)
    beautify_curl_output(p.stdout, hide_headers)


# Load the settings once before we start up
settings = Settings()


def main():
    parser = argparse.ArgumentParser(description="curl, with flames on top",
                                     add_help=False)
    parser.add_argument('-h', '--help', action='store_true',
                        help='Prints this help.')
    parser.add_argument('--site', help='The site to use.  By default it will '
                        'guess the site from the URL of the request.')
    parser.add_argument('--clear-token-cache', action='store_true',
                        help='Clears the token cache.  By default of all the '
                             'sites, can be limited to one site with --site.')
    parser.add_argument('--add-site', help='Registers a new site with curlish.',
                        metavar='NAME')
    parser.add_argument('--remove-site', help='Unregisters a site from curlish.',
                        metavar='NAME')
    parser.add_argument('--list-sites', help='Lists all known sites',
                        action='store_true')

    try:
        args, extra_args = parser.parse_known_args()
    except Exception as e:
        print e
        sys.exit(1)

    if args.help:
        parser.print_help()
        print __doc__.rstrip()
        return

    # Custom commands
    if args.clear_token_cache:
        clear_token_cache(args.site)
        return
    if args.add_site:
        add_site(args.add_site)
        return
    if args.remove_site:
        remove_site(args.remove_site)
        return
    if args.list_sites:
        list_sites()
        return

    # Redirect everything else to curl via the site
    url_arg = find_url_arg(extra_args)
    if url_arg is None:
        parser.print_usage()
        return
    site = get_site(args.site, extra_args[url_arg])
    if site is not None and site.grant_type is not None:
        site.fetch_token_if_necessarys()
    settings.save()
    invoke_curl(site, settings.values['curl_path'], extra_args, url_arg)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
