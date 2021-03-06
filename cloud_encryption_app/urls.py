"""aws_redis_imagenes URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from web import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('download-file/<str:filename>/<str:username>', views.download_file, name='download-file'),
    path('login/', views.login, name='login'),
    path('logout', views.logout, name='logout'),
    path('create-user', views.create_user, name='create-user'),
    path('delete-file/<str:filename>/<str:username>', views.delete_file, name='delete-file'),
    path('upload-file/<str:username>', views.APIUpload.as_view(), name='upload-file'),
    path('api-login', views.APILogin.as_view(), name='api-login'),
    path('api-get-file/<str:filename>/<str:username>', views.APIGetFile.as_view(), name='api-get-file'),
    path('api-get-files/<str:username>', views.APIGetFiles.as_view(), name='api-get-files'),
    path('api-delete-file/<str:username>/<str:filename>', views.APIDeleteFile.as_view(), name='api-delete-file')
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
