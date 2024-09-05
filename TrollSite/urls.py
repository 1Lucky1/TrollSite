"""
URL configuration for TrollSite project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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
from trololo.views import *
from django.shortcuts import redirect
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', index_redirect),
    path('index/', index, name='index'),
    path('admin/', admin.site.urls),
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    path('create-topic/', create_topic, name='create-topic'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('topic/<int:topic_id>/', topic_detail, name='topic_detail'),
]
