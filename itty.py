"""
The itty-bitty Python web framework.
"""
import cgi
import mimetypes
import os
import re
from io import BytesIO
import sys
import traceback
from typing import Dict, Union, Callable, List, Tuple, Optional
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

__orig_author__ = 'Daniel Lindsley'
__author__ = 'Don Welch'
__version__ = ('1', '0', '0')
__license__ = 'BSD'


REQUEST_MAPPINGS = {
    'GET': [],
    'POST': [],
    'PUT': [],
    'DELETE': [],
}

ERROR_HANDLERS = {}

MEDIA_ROOT = os.path.join(os.path.dirname(__file__), 'media')

HTTP_MAPPINGS = {
    100: 'CONTINUE',
    101: 'SWITCHING PROTOCOLS',
    200: 'OK',
    201: 'CREATED',
    202: 'ACCEPTED',
    203: 'NON-AUTHORITATIVE INFORMATION',
    204: 'NO CONTENT',
    205: 'RESET CONTENT',
    206: 'PARTIAL CONTENT',
    300: 'MULTIPLE CHOICES',
    301: 'MOVED PERMANENTLY',
    302: 'FOUND',
    303: 'SEE OTHER',
    304: 'NOT MODIFIED',
    305: 'USE PROXY',
    306: 'RESERVED',
    307: 'TEMPORARY REDIRECT',
    400: 'BAD REQUEST',
    401: 'UNAUTHORIZED',
    402: 'PAYMENT REQUIRED',
    403: 'FORBIDDEN',
    404: 'NOT FOUND',
    405: 'METHOD NOT ALLOWED',
    406: 'NOT ACCEPTABLE',
    407: 'PROXY AUTHENTICATION REQUIRED',
    408: 'REQUEST TIMEOUT',
    409: 'CONFLICT',
    410: 'GONE',
    411: 'LENGTH REQUIRED',
    412: 'PRECONDITION FAILED',
    413: 'REQUEST ENTITY TOO LARGE',
    414: 'REQUEST-URI TOO LONG',
    415: 'UNSUPPORTED MEDIA TYPE',
    416: 'REQUESTED RANGE NOT SATISFIABLE',
    417: 'EXPECTATION FAILED',
    500: 'INTERNAL SERVER ERROR',
    501: 'NOT IMPLEMENTED',
    502: 'BAD GATEWAY',
    503: 'SERVICE UNAVAILABLE',
    504: 'GATEWAY TIMEOUT',
    505: 'HTTP VERSION NOT SUPPORTED',
}


class RequestError(Exception):
    """
    A base exception for HTTP errors to inherit from.
    """
    status: int = 400

    def __init__(self, message: str, hide_traceback: bool=False):
        super().__init__(message)
        self.hide_traceback: bool = hide_traceback


class BadRequest(RequestError):
    status: int = 400


class Forbidden(RequestError):
    status: int = 403


class NotFound(RequestError):
    status: int = 404

    def __init__(self, message: str, hide_traceback: bool=True):
        super().__init__(message)
        self.hide_traceback: bool = hide_traceback


class ServerError(RequestError):
    status: int = 500


class Redirect(RequestError):
    """
    Redirects the user to a different URL.

    Slightly different than the other HTTP errors, the Redirect is less
    'OMG Error Occurred' and more 'let's do something exceptional'. When you
    redirect, you break out of normal processing anyhow, so it's a very similar
    case."""
    status = 302
    url = ''

    def __init__(self, url: str):
        self.url = url
        self.args = [f"Redirecting to {self.url!r}..."]


class HTTPHeaders(dict):
    """
    A dictionary that maintains Http-Header-Case for all keys.
    """
    def __init__(self, *args, **kwargs):
        dict.__init__(self)
        self._as_list = {}
        self._last_key = None
        if len(args) == 1 and len(kwargs) == 0 and isinstance(args[0], HTTPHeaders):
            for k, v in args[0].get_all():
                self.add(k, v)
        else:
            self.update(*args, **kwargs)


    def add(self, name: str, value: str) -> None:
        """
        Adds a new value for the given key.
        """
        norm_name = HTTPHeaders._normalize_name(name)
        self._last_key = norm_name
        if norm_name in self:
            dict.__setitem__(self, norm_name, str(self[norm_name]) + ',' + str(value))
            self._as_list[norm_name].append(value)
        else:
            self[norm_name] = value

    def get_list(self, name: str) -> List:
        """
        Returns all values for the given header as a list.
        """
        norm_name = HTTPHeaders._normalize_name(name)
        return self._as_list.get(norm_name, [])


    def get_all(self) -> Tuple[str, str]:
        """
        Returns an iterable of all (name, value) pairs.

        If a header has multiple values, multiple pairs will be
        returned with the same name.
        """
        for name, list_ in self._as_list.items():
            for value in list_:
                yield (name, value)


    def parse_line(self, line: str) -> None:
        """
        Updates the dictionary with a single header line.
        """
        if line[0].isspace():
            # continuation of a multi-line header
            new_part = ' ' + line.lstrip()
            self._as_list[self._last_key][-1] += new_part
            dict.__setitem__(self, self._last_key, self[self._last_key] + new_part)
        else:
            name, value = line.split(":", 1)
            self.add(name, value.strip())


    @classmethod
    def parse(cls, headers: str) -> 'HTTPHeaders':
        """
        Returns a dictionary from HTTP header text.
        """
        h = cls()
        [h.parse_line(line) for line in headers.splitlines() if line]
        return h


    def __setitem__(self, name: str, value: str) -> None:
        norm_name = HTTPHeaders._normalize_name(name)
        dict.__setitem__(self, norm_name, value)
        self._as_list[norm_name] = [value]


    def __getitem__(self, name: str) -> None:
        return dict.__getitem__(self, HTTPHeaders._normalize_name(name))


    def __delitem__(self, name: str) -> None:
        norm_name = HTTPHeaders._normalize_name(name)
        dict.__delitem__(self, norm_name)
        del self._as_list[norm_name]


    def __contains__(self, name: str) -> bool:
        norm_name = HTTPHeaders._normalize_name(name)
        return dict.__contains__(self, norm_name)


    def get(self, name: str, default: str=None) -> str:
        return dict.get(self, HTTPHeaders._normalize_name(name), default)


    def update(self, *args, **kwargs) -> None:
        for k, v in dict(*args, **kwargs).items():
            self[k] = v


    def copy(self) -> 'HTTPHeaders':
        return HTTPHeaders(self)

    _NORMALIZED_HEADER_RE = re.compile(r"""^[A-Z0-9][a-z0-9]*(-[A-Z0-9][a-z0-9]*)*$""")
    _normalized_headers = {}


    @staticmethod
    def _normalize_name(name: str) -> str:
        """
        Converts a name to Http-Header-Case.
        """
        try:
            return HTTPHeaders._normalized_headers[name]
        except KeyError:
            if HTTPHeaders._NORMALIZED_HEADER_RE.match(name):
                normalized = name
            else:
                normalized = "-".join([w.capitalize() for w in name.split("-")])
            HTTPHeaders._normalized_headers[name] = normalized
            return normalized


class Response:
    def __init__(self, output: Union[str, bytes], headers: Optional[Union[Dict, List]]=None,
                 status: int=200, content_type: str='text/html'):
        """
        Response object.
        :param output:
        :param headers:
        :param status:
        :param content_type:
        """
        self.output = output
        self.content_type = content_type
        self.status = status
        self.headers = HTTPHeaders()

        if headers and isinstance(headers, HTTPHeaders):
            self.headers = headers
        if headers and isinstance(headers, list):
            for (key, value) in headers:
                self.headers.add(key, value)


    def add_header(self, key: str, value: str) -> None:
        self.headers.add(key, value)


    def send(self, start_response: Callable):
        status = f"{self.status} {HTTP_MAPPINGS.get(self.status)}"
        headers = ([('Content-Type', f"{self.content_type}; charset=utf-8")] + [(k, v) for k, v in self.headers.items()])

        start_response(status, headers)

        if isinstance(self.output, str):
            return [self.output.encode('utf-8')]
        else:
            return [self.output]


class Request:
    """
    An object to wrap the environ bits in a friendlier way.
    """
    def __init__(self, environ: Dict, start_response: Callable):
        print(type(start_response))
        self._environ = environ
        self._start_response = start_response
        self.path = add_trailing_char(self._environ.get('PATH_INFO', ''), '/')
        self.method = self._environ.get('REQUEST_METHOD', 'GET').upper()
        self.query = self._environ.get('QUERY_STRING', '')
        self.content_length = 0
        self.headers = HTTPHeaders()
        self._payload = None
        self._body = None
        self._query_strings = None
        if self._environ.get("CONTENT_TYPE"):
            self.headers["Content-Type"] = self._environ["CONTENT_TYPE"]

        if self._environ.get("CONTENT_LENGTH"):
            self.headers["Content-Length"] = self._environ["CONTENT_LENGTH"]

        for key in self._environ:
            if key.startswith("HTTP_"):
                self.headers[key[5:].replace("_", "-")] = self._environ[key]

        try:
            self.content_length = int(self._environ.get('CONTENT_LENGTH', '0'))
        except ValueError:
            pass

    @property
    def query_strings(self):
        if self._query_strings is None:
            self._query_strings = self.build_qs_dict()
        return self._query_strings


    def getenv(self, name: str):
        return self._environ.get(name)

    @property
    def payload(self):
        if self._payload is None:
            self._payload = self.build_payload_dict()
        return self._payload


    @property
    def body(self) -> str:
        """
        Content of the request.
        """
        if self._body is None:
            self._body = self._environ['wsgi.input'].read(self.content_length)
        return self._body


    def build_qs_dict(self) -> Dict:
        """
        Takes GET data and rips it apart into a dict.
        """
        raw_query_dict = parse_qs(self.query, keep_blank_values=1)
        query_dict = {}

        for key, value in raw_query_dict.items():
            if len(value) <= 1:
                query_dict[key] = value[0]
            else:
                # Since it's a list of multiple items, we must have seen more than
                # one item of the same name come in. Store all of them.
                query_dict[key] = value

        return query_dict


    def build_payload_dict(self) -> Dict:
        """
        Takes POST/PUT data and rips it apart into a dict.
        """
        raw_data = cgi.FieldStorage(fp=BytesIO(self._body), environ=self._environ)
        query_dict = {}

        for field in raw_data:
            if isinstance(raw_data[field], list):
                # Since it's a list of multiple items, we must have seen more than
                # one item of the same name come in. Store all of them.
                query_dict[field] = [fs.value for fs in raw_data[field]]
            elif raw_data[field].filename:
                # We've got a file.
                query_dict[field] = raw_data[field]
            else:
                query_dict[field] = raw_data[field].value

        return query_dict


def handle_request(environ: Dict, start_response: Callable):
    """
    The main handler. Dispatches to the user's code.
    """
    print(f"handle_request({environ!r}, {start_response!r})")
    try:
        request = Request(environ, start_response)
    except Exception as e:
        return handle_error(e)

    try:
        (re_url, url, callback), kwargs = find_matching_url(request)
        print(re_url)
        print(url)
        print(callback)
        response = callback(request, **kwargs)
    except Exception as e:
        return handle_error(e, request)

    print(response)
    if not isinstance(response, Response):
        response = Response(response)

    return response.send(start_response)


def handle_error(exception: Exception, request: Request=None):
    """
    If an exception is thrown, deal with it and present an error page.
    """
    if request is None:
        request = {'_environ': {'PATH_INFO': ''}}

    if not getattr(exception, 'hide_traceback', False):
        (e_type, e_value, e_tb) = sys.exc_info()
        message = f"{exception.__class__} occurred on {request._environ['PATH_INFO']!r}: {exception}" \
                  f"\n{''.join(traceback.format_exception(e_type, e_value, e_tb))}"
        request._environ['wsgi.errors'].write(message)

    if isinstance(exception, RequestError):
        status = getattr(exception, 'status', 404)
    else:
        status = 500

    if status in ERROR_HANDLERS:
        return ERROR_HANDLERS[status](request, exception)

    return not_found(request, exception)


def find_matching_url(request: Request) -> Tuple[Tuple[str, str, Callable], Dict]:
    """
    Searches through the methods who've registed themselves with the HTTP decorators.
    """
    if request.method not in REQUEST_MAPPINGS:
        raise NotFound(f"The HTTP request method '{request.method}' is not supported.")

    for url_set in REQUEST_MAPPINGS[request.method]:
        match = url_set[0].match(request.path)

        if match is not None:
            return url_set, match.groupdict()

    raise NotFound("Sorry, nothing here.")


def add_trailing_char(s: str, char: str) -> str:
    return s + char if not s.endswith(char) else s


def add_leading_char(s: str, char: str) -> str:
    return char + s if not s.startswith(char) else s


def guess_content_type(filename: str) -> str:
    """
    Takes a guess at what the desired mime type might be for the requested file.
    Mostly only useful for static media files.
    """
    ct = 'text/plain'
    ct_guess = mimetypes.guess_type(filename)

    if ct_guess[0] is not None:
        ct = ct_guess[0]

    return ct


def static_file(filename: str, root: str=MEDIA_ROOT) -> Union[bytes, str]:
    """
    Fetches a static file from the filesystem, relative to either the given
    MEDIA_ROOT or from the provided root directory.
    """
    if filename is None:
        raise Forbidden("You must specify a file you'd like to access.")

    # Strip the '/' from the beginning/end.
    valid_path = filename.strip('/')

    # Kill off any character trying to work their way up the filesystem.
    valid_path = valid_path.replace('//', '/').replace('/./', '/').replace('/../', '/')

    desired_path = os.path.join(root, valid_path)

    if not os.path.exists(desired_path):
        raise NotFound("File does not exist.")

    if not os.access(desired_path, os.R_OK):
        raise Forbidden("You do not have permission to access this file.")

    ct = str(guess_content_type(desired_path))

    # Do the text types as a non-binary read.
    if ct.startswith('text') or ct.endswith('xml') or ct.endswith('json'):
        return open(desired_path, 'r').read()

    # Fall back to binary for everything else.
    return open(desired_path, 'rb').read()


# Static file handler

def serve_static_file(request: Request, filename: str, root: str=MEDIA_ROOT, force_content_type: Optional[str]=None) -> Response:
    """
    Basic handler for serving up static media files.

    Accepts an optional ``root`` (filepath string, defaults to ``MEDIA_ROOT``) parameter.
    Accepts an optional ``force_content_type`` (string, guesses if ``None``) parameter.
    """
    file_contents = static_file(filename, root)

    if force_content_type is None:
        ct = guess_content_type(filename)
    else:
        ct = force_content_type

    return Response(file_contents, content_type=ct)


# Decorators

embedded_pat = re.compile(r"({([a-z_][a-z0-9_]+)})", re.I)


def compile_route(route: str) -> re.Pattern:
    """
    Compile routes with (optional) embedded {var} name(s).
    /get/{one}/and/{two}  -->  ^/get/(?P<one>[a-z0-9_ .]+)/and/(?P<two>[a-z0-9_ .]+)/$
    Each var must represent a valid Python identifier and
    must be the parameter name(s) to the registered (decorated) function.
    """
    route = add_leading_char(add_trailing_char(add_trailing_char(route, '/'), '$'), '^')
    print(f"Compiling route: {route}")
    while True:
        match = embedded_pat.search(route)
        if match is not None:
            pattern = f"(?P<{match.group(2)}>[a-z0-9_ .-]+)"
            print(pattern)
            route = embedded_pat.sub(pattern, route, 1)
            print(route)
        else:
            break

    return re.compile(route, re.I)


def register(action: str, url: str) -> Callable:
    """
    Registers a method as capable of processing a request.
    """
    action = action.upper()
    print(f"Registering route: ({action}, {url})")

    def wrapped(method):
        def new(request, *args, **kwargs):
            return method(request, *args, **kwargs)
        # Register
        compiled_route = compile_route(url)
        REQUEST_MAPPINGS[action].append((compiled_route, url, new))
        if action == 'PUT':
            new.status = 201
        return new
    return wrapped


def error(code: int):
    """
    Registers a method for processing errors of a certain HTTP code.
    """
    def wrapped(method):
        # Register.
        ERROR_HANDLERS[code] = method
        return method
    return wrapped


# Error handlers

@error(403)
def forbidden(request: Request, _):
    response = Response('Forbidden', status=403, content_type='text/plain')
    return response.send(request._start_response)


@error(404)
def not_found(request: Request, _):
    response = Response('Not Found', status=404, content_type='text/plain')
    return response.send(request._start_response)


@error(500)
def app_error(request: Request, _):
    response = Response('Server Error', status=500, content_type='text/plain')
    return response.send(request._start_response)


@error(302)
def redirect(request: Request, exception: Redirect):
    response = Response('', status=302, content_type='text/plain', headers=[('Location', exception.url)])
    return response.send(request._start_response)


def run_itty(host: str='0.0.0.0', port: int=8080, config: str=None) -> None:
    """
    Runs the itty web server.
    Accepts an optional host (string), port (integer), and config (python module name/path as a string) parameters.
    """

    if config is not None:
        # We'll let ImportErrors bubble up.
        config_options = __import__(config)
        host = getattr(config_options, 'host', host)
        port = getattr(config_options, 'port', port)

    print(f"Web server starting up, listening on http://{host}:{port}...")
    print('Ctrl-C to quit.')
    print()

    try:
        srv = make_server(host, port, handle_request)
        srv.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down...")
        sys.exit(0)
    except OSError as e:
        print(f"Error: {e}")
        sys.exit(1)

