import os

from django.shortcuts import render
from cryptography.fernet import Fernet
from os import mkdir
from cloud_encryption_app.settings import FILES

key_init = b'E4670MtgbdM1K_KjEBDWg467YB2RIXeXIC8HwnGUWlc='

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
            chunk += b'0' * padding

        yield chunk


# Create your views here.
def index(request):
    context = {}

    filename = ''
    user = 'Jose'
    context['username'] = user
    dir = FILES + '/' + user

    context['uploaded_files'] = os.listdir(dir)
    with open('./web/FernetKey.key', 'rb') as f_key:
        key = f_key.read()

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
            fernet_key = Fernet(key_init)
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

def download_file(request, filename, username):
    user = 'Jose'
    with open(f'{FILES}/{username}/{filename}', 'rb') as encrypted_file:
        file = encrypted_file.read()

    chunked_content = chunk_bytes(size=440, source=file)
    content = b''
    with open('./web/FernetKey.key', 'rb') as f_key:
        key = f_key.read()

    fernet_key = Fernet(key_init)

    for chunk in chunked_content:
        content += fernet_key.decrypt(chunk)
    with open(f'{FILES}/{user}/{filename}', 'wb') as decrypted_file:
        decrypted_file.write(content)
    return None