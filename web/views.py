from django.shortcuts import render

# Create your views here.
def index(request):
    context = {}

    filename = ''

    if request.FILES:
        if 'file' in request.FILES and request.FILES['file']:
            filename = request.FILES['file'].name

    return render(request, "index.html", context)
