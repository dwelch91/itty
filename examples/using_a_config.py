from itty import *


@register('get', '/')
def index(request):
    return 'Hello World!'


run_itty(config='sample_conf')
