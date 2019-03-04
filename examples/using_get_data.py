from itty import *


@register('get', '/')
def test_get(request):
    return "'foo' is: %s" % request.payload().get('foo', 'not specified')


run_itty()
