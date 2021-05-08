import base64
import json
import os

# Login
import requests
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
from rest_framework import views, response, status


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
    if uploaded_files:
        context['uploaded_files'] = UploadedFile.objects.filter(username=username, filename__in=uploaded_files)

    if request.FILES:
        if 'file' in request.FILES and request.FILES['file']:
            encrypt_file(request, username)

            return redirect('index')

    return render(request, "index.html", context)


def encrypt_file(request, username):
    if User.objects.filter(username=username).exists():
        filename = request.FILES['file'].name
        content = b''
        for chunk in request.FILES['file'].chunks():
            content += chunk

        # Generate unique fernet key for uploaded file
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'',
            iterations=100000
        )
        user_pass = User.objects.get(username=username).password
        key = base64.urlsafe_b64encode(kdf.derive(user_pass.encode()))
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

        response = requests.get('http://127.0.0.1:8082/wrapped-key/' + key.decode()).content.decode()
        json_res = json.loads(response)
        WDEK = json_res['DEK']

        if UploadedFile.objects.filter(filename=filename, username=username).exists():
            UploadedFile.objects.filter(filename=filename, username=username).update(encryption_key=WDEK,
                                                created_at=datetime.datetime.now())
        else:
            UploadedFile.objects.create(
                filename=filename,
                encryption_key=WDEK,
                created_at=datetime.datetime.now(),
                username=username
            )


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


class APIUpload(views.APIView):
    @staticmethod
    def post(request):
        """
        Upload File to Cloud Storage System
        :param request: HTTP request
        :return: JSON response
        """
        encrypt_file(request, 'Jose1001')
        return response.Response(data={'message': 'File upload successfully'}, status=status.HTTP_200_OK)


class APILogin(views.APIView):
    @staticmethod
    def get(request):
        """
        Login by HTTP request
        :param request: HTTP request
        :return: JSON response
        """

        password = request.POST['pass']
        username = request.POST['user']
        res_status = status.HTTP_403_FORBIDDEN
        message = 'Invalid login'
        user = authenticate(username=username, password=password)
        if user:
            res_status = status.HTTP_200_OK
            message = 'Successfully Login'

        return response.Response(data={'message': message}, status=res_status)
