# xss_shield.py
# =============================================================================
# XSS SHIELD — защита от XSS-атак на Python
# Автор: m2xdev
# Лицензия: MIT
#
# ДАННЫЙ КОД ПРЕДОСТАВЛЯЕТСЯ "КАК ЕСТЬ", БЕЗ ГАРАНТИЙ.
# АВТОР НЕ НЕСЁТ ОТВЕТСТВЕННОСТИ ЗА ЛЮБОЙ УЩЕРБ.
#
# Зависимости: pip install nh3
# =============================================================================

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

import nh3

# =============================================================================
# БЕЛЫЕ СПИСКИ
# =============================================================================

# Безопасные теги
ALLOWED_TAGS: Set[str] = {
    'p', 'br', 'b', 'i', 'u', 'strong', 'em', 'span', 'div',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li',
    'a', 'img',
    'pre', 'code', 'blockquote', 'hr',
    'table', 'thead', 'tbody', 'tr', 'td', 'th',
}

# Безопасные атрибуты.
# НАМЕРЕННО НЕ РАЗРЕШЕНЫ:
#   style  → CSS-инъекции, кликджекинг, эксфильтрация данных
#   id     → DOM Clobbering
#   on*    → обработчики событий (onclick, onerror и т.д.)
#   target → reverse tabnabbing (вместо него link_rel добавляет noopener)
ALLOWED_ATTRIBUTES: Dict[str, Set[str]] = {
    '*': {'class'},
    'a': {'href', 'title'},
    'img': {'src', 'alt', 'title', 'width', 'height'},
}

# Разрешённые URL-схемы.
# Заблокированы: javascript:, data:, vbscript:, ftp:
ALLOWED_SCHEMES: Set[str] = {'http', 'https', 'mailto'}


# =============================================================================
# ОСНОВНЫЕ ФУНКЦИИ
# =============================================================================

def strip_xss(text: str) -> str:
    """
    Очищает строку от XSS-кода, оставляя только безопасный HTML.

    Использует nh3 (Rust-биндинги к ammonia) — быстрая и активно
    поддерживаемая библиотека для санации HTML.

    Args:
        text: Входная строка.

    Returns:
        Очищенная строка.

    Raises:
        TypeError: Если передан не str (кроме None).
    """
    if text is None:
        return ''
    if not isinstance(text, str):
        raise TypeError(f"strip_xss() ожидает str, получен {type(text).__name__}")

    return nh3.clean(
        text,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes=ALLOWED_SCHEMES,
        link_rel='noopener noreferrer',  # защита от reverse tabnabbing
        strip_comments=True,
    )


def safe_render(value: Any) -> Any:
    """
    Рекурсивно очищает все строки в списках и словарях.

    - None возвращается как есть (не превращается в '').
    - Числа, bool и прочие не-строки возвращаются без изменений.
    - Строки проходят через strip_xss().
    - Строковые ключи словарей тоже очищаются.

    Args:
        value: Любое значение (str, list, dict, None, число и т.д.).

    Returns:
        Очищенная структура с сохранением типов.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return strip_xss(value)
    if isinstance(value, list):
        return [safe_render(item) for item in value]
    if isinstance(value, dict):
        return {
            strip_xss(k) if isinstance(k, str) else k: safe_render(v)
            for k, v in value.items()
        }
    return value


class XSSShield:
    """
    Класс для массовой очистки входных данных (формы, API-запросы).

    Пример:
        shield = XSSShield(skip_fields=['password', 'csrf_token'])
        cleaned = shield.clean_input(request_data)
    """

    def __init__(self, skip_fields: Optional[List[str]] = None):
        """
        Args:
            skip_fields: Поля, которые НЕ нужно чистить
                         (пароли, токены и т.д.).
        """
        self.skip_fields: Set[str] = set(
            skip_fields if skip_fields is not None
            else ['csrf_token', 'password', 'secret']
        )

    def clean_input(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Очищает все поля входных данных, кроме полей из skip_fields.

        Args:
            data: Словарь входных данных.

        Returns:
            Новый словарь с очищенными значениями.
        """
        cleaned: Dict[str, Any] = {}
        for key, value in data.items():
            if key in self.skip_fields:
                cleaned[key] = value
            else:
                cleaned[key] = safe_render(value)
        return cleaned

    # Примечание: намеренно НЕТ метода clean_response().
    # Выходные данные должны экранироваться шаблонизатором (autoescape),
    # а не санитизироваться повторно. Повторная санация приводит к
    # двойному экранированию (&amp;lt; вместо &lt;).


# =============================================================================
# ТЕСТЫ
# =============================================================================

def _run_tests() -> None:
    """Проверка работоспособности щита."""
    print("🛡️  КАПИБАРА ТЕСТИРУЕТ XSS ЩИТ")
    print("=" * 62)

    passed = 0
    failed = 0

    def check(name: str, condition: bool) -> None:
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  ✅ {name}")
        else:
            failed += 1
            print(f"  ❌ {name}")

    # --- strip_xss: блокировка атак ---
    r = strip_xss("<script>alert(1)</script>")
    check("удаляет <script>", "<script" not in r.lower())

    r = strip_xss("<img src=x onerror=alert(1)>")
    check("удаляет onerror", "onerror" not in r.lower())

    r = strip_xss("<a href='javascript:alert(1)'>x</a>")
    check("блокирует javascript:", "javascript:" not in r.lower())

    r = strip_xss("<div onclick='foo()'>text</div>")
    check("удаляет onclick", "onclick" not in r.lower())

    r = strip_xss('<div style="background:url(evil)">x</div>')
    check("удаляет style-атрибут", "style" not in r.lower())

    r = strip_xss('<div id="config">x</div>')
    check("удаляет id-атрибут (DOM Clobbering)", 'id=' not in r.lower())

    # --- strip_xss: сохранение безопасного контента ---
    r = strip_xss('<a href="https://example.com">link</a>')
    check("сохраняет безопасные ссылки + noopener",
          'href="https://example.com"' in r and 'noopener' in r)

    r = strip_xss("<b>bold</b> <i>italic</i>")
    check("сохраняет безопасные теги",
          "<b>bold</b>" in r and "<i>italic</i>" in r)

    check("обычный текст без изменений", strip_xss("hello world") == "hello world")
    check("None → пустая строка", strip_xss(None) == "")

    # --- safe_render ---
    data = {
        "name": "<script>x</script>",
        "items": ["<b>ok</b>", {"nested": "<img src=x onerror=y>"}],
        "count": 42,
        "flag": True,
        "empty": None,
    }
    cleaned = safe_render(data)
    check("рекурсивно чистит вложенные структуры",
          "<script" not in str(cleaned) and "onerror" not in str(cleaned))
    check("сохраняет числа", cleaned["count"] == 42)
    check("сохраняет bool", cleaned["flag"] is True)
    check("сохраняет None", cleaned["empty"] is None)

    # --- XSSShield ---
    shield = XSSShield(skip_fields=["password"])
    req = {"password": "<b>secret</b>", "comment": "<script>alert(1)</script>"}
    out = shield.clean_input(req)
    check("skip_fields не чистятся", out["password"] == "<b>secret</b>")
    check("остальные поля чистятся", "<script" not in out["comment"])

    # --- Итог ---
    print("=" * 62)
    print(f"Результат: {passed} прошло, {failed} упало")
    if failed == 0:
        print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ! ЩИТ РАБОТАЕТ!")
    else:
        print("⚠️  ЕСТЬ ПАДЕНИЯ — капибара расстроена 😿")


if __name__ == '__main__':
    _run_tests()
    print("\n📦 Установка: pip install nh3")