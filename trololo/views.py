from django.contrib.auth import login
from django.shortcuts import render, get_object_or_404, redirect
import re

from .forms import RegistrationForm, LoginForm
from .forms import TopicForm, CommentForm
from .models import Topic, Comment
from django.contrib import messages


# Create your views here.


def index_redirect(request):
    return redirect('index')


def index(request):
    topics = Topic.objects.all()  # Получаем все топики из базы данных
    return render(request, 'index.html', {'topics': topics,
                                          'malicious_attempt': getattr(request, 'malicious_attempt', False),
                                          })  # Передаем список топиков в шаблон


def register_view(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if getattr(request, 'malicious_attempt', False):
            form.add_error(None, "Обнаружены запрещённые символы в вашем запросе.")
        elif form.is_valid():
            user = form.save()
            login(request, user)  # Автоматически аутентифицируем пользователя после регистрации
            return redirect('/')  # Перенаправление на главную страницу или другую
    else:
        form = RegistrationForm()
    return render(request, 'register.html', {'form': form,
                                             'malicious_attempt': getattr(request, 'malicious_attempt', False),
                                             })


def login_view(request):
    if request.method == 'POST':
        form = LoginForm(data=request.POST)
        if getattr(request, 'malicious_attempt', False):
            form.add_error(None, "Обнаружены запрещённые символы в вашем запросе.")
        elif form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('/')  # Перенаправление на главную страницу или другую
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form,
                                          'malicious_attempt': getattr(request, 'malicious_attempt', False),
                                          })


def create_topic(request):
    if request.method == 'POST':
        form = TopicForm(request.POST)
        if getattr(request, 'malicious_attempt', False):
            form.add_error(None, "Обнаружены запрещённые символы в вашем запросе.")
        if form.is_valid():
            topic = form.save(commit=False)
            topic.author = request.user  # Указываем пользователя как автора
            topic.save()
            return redirect('index')
    else:
        form = TopicForm()

    return render(request, 'create-topic.html', {'form': form,
                                                 'malicious_attempt': getattr(request, 'malicious_attempt', False),
                                                 })


def topic_detail(request, topic_id):
    topic = get_object_or_404(Topic, id=topic_id)
    comments = Comment.objects.filter(topic=topic)
    if request.method == 'POST':
        form = CommentForm(request.POST)
        if form.is_valid():
            content = form.cleaned_data.get('content')
            # Проверка на запрещённые символы
            forbidden_patterns = [
                r'<script.*?>',  # XSS
                r'{{.*}}',       # SSTI
                r'\bselect\b',   # SQL Injection
                r'\bunion\b',    # SQL Injection
                r'\bexec\b',     # Command Injection
                r'\bsystem\b',   # Command Injection
            ]
            if any(re.search(pattern, content, re.IGNORECASE) for pattern in forbidden_patterns):
                request.malicious_attempt = True
                return render(request, 'topic-detail.html', {
                    'topic': topic,
                    'comments': comments,
                    'comment_form': form,
                    'malicious_attempt': True,
                })
            else:
                comment = form.save(commit=False)
                comment.author = request.user
                comment.topic = topic
                comment.save()
                messages.success(request, 'Комментарий добавлен!')
                return redirect('topic_detail', topic_id=topic.id)
    else:
        form = CommentForm()

    return render(request, 'topic-detail.html', {
        'topic': topic,
        'comments': comments,
        'comment_form': form,
        'malicious_attempt': getattr(request, 'malicious_attempt', False),
    })
