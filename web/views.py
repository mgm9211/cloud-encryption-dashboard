from django.shortcuts import render
from cryptography.fernet import Fernet
from os import mkdir
from cloud_encryption_app.settings import FILES


def chunk_bytes(size, source):
    """
    Return list with chunks of the source data
    :param size: size of chunks
    :param source: bytes string to separate in chunks
    :return: list with bytes string separate in chunks
    """
    for i in range(0, len(source), size):
        chunk = source[i:i+size]
        if len(chunk) < size:
            padding = size - len(chunk)
            zero_padding = 0
            chunk += zero_padding.to_bytes(1,'big') * (padding-1)
            chunk += padding.to_bytes(1,'big')
            print(chunk)
            print(len(chunk))
            print((size))

        yield chunk


# Create your views here.
def index(request):
    context = {}

    filename = ''
    user = 'Jose'

    if request.FILES:
        if 'file' in request.FILES and request.FILES['file']:
            filename = request.FILES['file'].name
            cont = 0
            content = b''
            for chunk in request.FILES['file'].chunks():
                content += chunk

            with open('./web/FernetKey.key', 'rb') as f_key:
                key = f_key.read()

            chunked_content = chunk_bytes(size=256, source=content)
            fernet_key = Fernet(key)
            encrypted_content = b''
            for c in chunked_content:
                encrypted_content += fernet_key.encrypt(c)

            try:
                mkdir(f'{FILES}/{user}')
            except:
                print('Folder created')

            with open(f'{FILES}/{user}/{filename}', 'wb') as encrypted_file:
                encrypted_file.write(encrypted_content)

    return render(request, "index.html", context)
