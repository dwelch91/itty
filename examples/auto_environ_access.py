from itty import *


@register('get', '/')
def index(request):
    try:
        # Should raise an error.
        return 'What? Somehow found a remote user: %s' % request.getenv('REMOTE_USER')
    except KeyError:
        pass

    return "Remote Addr: '%s' & GET name: '%s'" % (request.getenv('REMOTE_ADDR'), request.payload.get('name', 'Not found'))

run_itty()
