from itty import *


@register('get', '/get/{name}')
def test_get(request, name=', world'):
    return 'Hello %s!' % name


@register('post', '/post')
def test_post(request):
    return "'foo' is: %s" % request.payload().get('foo', 'not specified')


@register('put', '/put')
def test_put(request):
    return "'foo' is: %s" % request.payload().get('foo', 'not specified')


@register('delete', '/delete')
def test_delete(request):
    return 'Method received was %s.' % request.method


run_itty()
