import re
from django.utils.deprecation import MiddlewareMixin


class InputSanitizationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.method in ['POST', 'GET']:
            # Проверка всех полей запроса на подозрительные символы
            for value in request.POST.values():
                if self.is_malicious(value):
                    request.malicious_attempt = True
                    return None  # Прекращаем обработку запроса
            for value in request.GET.values():
                if self.is_malicious(value):
                    request.malicious_attempt = True
                    return None  # Прекращаем обработку запроса
        request.malicious_attempt = False

    @staticmethod
    def is_malicious(value):
        # Пример простой проверки: наличие подозрительных символов
        patterns = [
            r'<script.*?>',  # XSS (Cross-Site Scripting)
            r'{{.*}}',  # SSTI (Server-Side Template Injection)
            r'\bselect\b',  # SQL Injection
            r'\bunion\b',  # SQL Injection
            r'\bexec\b',  # Command Injection
            r'\bsystem\b',  # Command Injection
            r'--\s',  # SQL Injection - комментарии
            r'\'\s*or\s*1\s*=\s*1',  # SQL Injection - логическое условие
            r'"\s*or\s*1\s*=\s*1',  # SQL Injection - логическое условие
            r'\bunion\s+select\b',  # SQL Injection - объединение запросов
            r'base64\s*:',  # Возможный скрытый код
            r'(?i)\bexec\b',  # Команды
            r'(?i)\bcmd\b',  # Команды Windows
            r'(?i)\bpowershell\b',  # Команды PowerShell
            r'(?i)\bphpinfo\b',  # Информация о PHP (опасная функция)
            r'(?i)\bpython\b',  # Команды Python
            r'(?i)\bbash\b',  # Команды Bash
            r'(?i)\bshell\b',  # Команды оболочки
            r'(?i)\bwrite-file\b',  # Команды записи в файл
            r'(?i)\bread-file\b',  # Команды чтения файла
            r'(?i)\bcat\b',  # Команда cat в Unix
            r'(?i)\btouch\b',  # Команда touch в Unix
            r'(?i)\bdump\b',  # SQL Dump
            r'(?i)\bwget\b',  # Команда wget
            r'(?i)\bcurl\b',  # Команда curl
        ]
        return any(re.search(pattern, value, re.IGNORECASE) for pattern in patterns)
