from itty import *


@register('get', '/upload')
def upload(request):
    return open('examples/html/upload.html', 'r').read()


@register('post', '/test_upload')
def test_upload(request):
    myfilename = ''

    if request.payload()['myfile'].filename:
        myfilename = request.payload()['myfile'].filename
        myfile_contents = request.payload()['myfile'].file.read()
        uploaded_file = open(myfilename, 'w')
        uploaded_file.write(myfile_contents)
        uploaded_file.close()

    html = """
    'foo' is: %s<br>
    'bar' is: %s
    """ % (request.payload().get('foo', 'not specified'), myfilename)
    return html

run_itty()
