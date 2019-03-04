from itty import *


@register('get', '/')
def index(request):
    print(request.body)
    print(request.payload)
    return 'Hello World!'

run_itty()
