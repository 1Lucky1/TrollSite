# forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import Topic, Comment
import re


class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'placeholder': 'Ваш комментарий...', 'rows': 3}),
        }

    # def clean_content(self):
    #     content = self.cleaned_data.get('content')
    #     # Простейшая проверка на наличие подозрительных символов
    #     forbidden_patterns = [
    #         r'<script.*?>',  # XSS
    #         r'{{.*}}',       # SSTI
    #         r'\bselect\b',   # SQL Injection
    #         r'\bunion\b',    # SQL Injection
    #         r'\bexec\b',     # Command Injection
    #         r'\bsystem\b',   # Command Injection
    #     ]
    #     if any(re.search(pattern, content, re.IGNORECASE) for pattern in forbidden_patterns):
    #         raise forms.ValidationError("Ваш комментарий содержит запрещённые символы.")
    #     return content


class TopicForm(forms.ModelForm):
    class Meta:
        model = Topic
        fields = ['name', 'description']
        labels = {
            'name': 'Название',
            'description': 'Описание',
        }
        widgets = {
            'name': forms.TextInput(attrs={'placeholder': 'Введите название'}),
            'description': forms.Textarea(attrs={'placeholder': 'Введите описание'}),
        }


class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']


class LoginForm(AuthenticationForm):
    pass
