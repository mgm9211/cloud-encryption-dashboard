import os

# Login
from django.contrib.auth import login as do_login
from django.contrib.auth import logout as do_logout
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
# END Login

from django.shortcuts import render
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os import mkdir
from cloud_encryption_app.settings import FILES
from django.http import HttpResponse
from django.shortcuts import redirect

from .forms import SignUpForm
import datetime
from web.models import AuthUser, UploadedFile
from django.contrib.auth.models import User


def chunk_bytes(size, source):
    """
    Return list with chunks of the source data
    :param size: size of chunks
    :param source: bytes string to separate in chunks
    :return: list with bytes string separate in chunks
    """
    for i in range(0, len(source), size):
        chunk = source[i:i + size]
        if len(chunk) < size:
            padding = size - len(chunk)
            zero_padding = 0
            chunk += zero_padding.to_bytes(1, 'big') * (padding - 1)
            chunk += padding.to_bytes(1, 'big')

        yield chunk


def login(request, user=None):
    context = {}

    if request and request.POST:
        username = request.POST['username']
        if 'password' in request.POST:
            password = request.POST['password']
        elif 'password1' in request.POST:
            password = request.POST['password1']
        else:
            password = ''
        user = authenticate(username=username, password=password)
        if user is not None:
            do_login(request, user)
            request.session['username'] = username
            return redirect('index')

    return render(request, "login.html", context)


@login_required
def logout(request):
    do_logout(request)
    return redirect('login')


# Create your views here.
@login_required
def index(request):
    context = {}

    filename = ''
    username = request.session.get('username')
    context['username'] = username
    dir = FILES + '/' + username

    uploaded_files = None
    if os.path.exists(dir):
        uploaded_files = os.listdir(dir)
        with open('./web/FernetKey.key', 'rb') as f_key:
            key = f_key.read()
    context['uploaded_files'] = uploaded_files

    if request.FILES:
        if 'file' in request.FILES and request.FILES['file']:
            if User.objects.filter(username=username).exists():
                filename = request.FILES['file'].name
                content = b''
                for chunk in request.FILES['file'].chunks():
                    content += chunk

                # Generate unique fernet key for uploaded file
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    iterations=100000,
                    backend=None
                )
                user_pass = User.objects.get(username=username).password
                print('---------> User pass: ', user_pass)
                key = kdf.derive(b"my great password")

                chunked_content = chunk_bytes(size=256, source=content)
                fernet_key = Fernet(key)
                encrypted_content = b''
                for c in chunked_content:
                    print(len(c))
                    en_c = fernet_key.encrypt(c)
                    print(len(en_c))
                    encrypted_content += en_c

                try:
                    mkdir(f'{FILES}/{username}')
                except:
                    print('Folder created')

                with open(f'{FILES}/{username}/{filename}', 'wb') as encrypted_file:
                    encrypted_file.write(encrypted_content)
                if UploadedFile.objects.filter(filename=filename, username=username).exists():
                    UploadedFile.objects.update(
                        filename=filename,
                        encryption_key=key.decode('UTF-8'),
                        created_at=datetime.datetime.now(),
                        username=username
                    )
                else:
                    UploadedFile.objects.create(
                        filename=filename,
                        encryption_key=key.decode('UTF-8'),
                        created_at=datetime.datetime.now(),
                        username=username
                    )

            return redirect('index')

    return render(request, "index.html", context)


@login_required
def download_file(request, filename, username):
    if UploadedFile.objects.filter(filename=filename, username=username).exists():
        with open(f'{FILES}/{username}/{filename}', 'rb') as encrypted_file:
            file = encrypted_file.read()

        chunked_content = chunk_bytes(size=440, source=file)
        content = b''
        key = UploadedFile.objects.get(filename=filename, username=username).encryption_key.encode('UTF-8')

        fernet_key = Fernet(key)
        path_file_temp = f'{FILES}/temp/' + filename

        for chunk in chunked_content:
            content += fernet_key.decrypt(chunk)

        end = int.from_bytes(content.strip()[-1:], 'big')
        content = content.strip()[:-end]

        with open(path_file_temp, 'wb') as decrypted_file:
            decrypted_file.write(content)

        if os.path.exists(path_file_temp):
            with open(path_file_temp, 'rb') as fh:
                response = HttpResponse(fh.read(), content_type="application/vnd.ms-excel")
                response['Content-Disposition'] = 'inline; filename=' + os.path.basename(path_file_temp)
                os.remove(os.path.join(path_file_temp))
                return response
        else:
            return None


def create_user(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect('index')
    else:
        form = SignUpForm()
    return render(request, '../templates/create-user.html', {'form': form})
