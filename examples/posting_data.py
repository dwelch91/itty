from itty import *

@register('get', '/simple_post')
def simple_post(request):
    return open('examples/html/simple_post.html', 'r').read()

@register('post', '/test_post')
def test_post(request):
    return "'foo' is: %s" % request.POST.get('foo', 'not specified')

@register('get', '/complex_post')
def complex_post(request):
    return open('examples/html/complex_post.html', 'r').read()

@register('post', '/test_complex_post')
def test_complex_post(request):
    html = """
    'foo' is: %s<br>
    'bar' is: %s
    """ % (request.POST.get('foo', 'not specified'), request.POST.get('bar', 'not specified'))
    return html

run_itty()
