# -*- coding: utf-8 -*-
from itty import *


@register('get', '/ct')
def ct(request):
    response = Response('Check your Content-Type headers.', content_type='text/plain')
    return response


@register('get', '/headers')
def test_headers(request):
    headers = [
        ('X-Powered-By', 'itty'),
    ]
    response = Response('Check your headers.', headers=headers)
    return response


@register('get', '/redirected')
def index(request):
    return 'You got redirected!'


@register('get', '/test_redirect')
def test_redirect(request):
    raise Redirect('/redirected')


@register('get', '/unicode')
def unicode(request):
    return u'Works with Unîcødé too!'


run_itty()
