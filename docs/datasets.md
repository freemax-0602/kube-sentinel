# Тестовая выборка Kubernetes audit logs

Подготовлено 05.11.2026 для тестирования preprocessing.

## Назначение

Набор предназначен для первоначальных тестов preprocessing pipeline проекта
AI-Kube-Log-Analyze и передачи U2. Для начала работы достаточно двух файлов:
[CSV](../data/samples/audit-logs.sample.csv) и
[JSON](../data/samples/audit-logs.sample.json).
Они содержат одни и те же события в одинаковом порядке.
Скрипт нужен только для повторного формирования выборки.

## Источник и условия

- Репозиторий: https://github.com/hkerma/kubernetes-event-dataset
- Исходный файл: https://github.com/hkerma/kubernetes-event-dataset/blob/main/raw-audit-logs.log
- Предоставленная локальная копия: `/Users/freemax0602/Downloads/raw-audit-logs.log`.
- Лицензия репозитория: CC BY 4.0, https://github.com/hkerma/kubernetes-event-dataset/blob/main/LICENSE.txt.
- Атрибуция: H. Kermabon-Bobinnec et al., «PerfSPEC: Performance Profiling-based Proactive Security Policy Enforcement for Containers», IEEE TDSC, 2024, DOI: 10.1109/TDSC.2024.3420712.

## Анализ предоставленного файла

Размер 92 794 383 байта. Формат JSON Lines: 94 287 объектов JSON,
ошибок JSON не обнаружено. Все записи имеют `level=Metadata`.
Поля `requestObject` и `responseObject` отсутствуют во всём файле:
это audit metadata, а не полные тела запросов/ответов.
`responseStatus` сохранён и может содержать подробности ошибки.
У 53 621 записей отсутствует `objectRef`; у 48 — `annotations`.
Всего 8 операций, 8 кодов HTTP и 2 стадии обработки.

## Результат

- `data/samples/audit-logs.sample.csv`: ровно 100 событий и заголовок.
- `data/samples/audit-logs.sample.json`: те же 100 событий в том же порядке,
  в виде JSON-массива объектов. Вложенные объекты, массивы и исходные типы
  сохранены; отсутствующие поля не добавляются. `source_line` — целое число.
- `data/samples/audit-logs.sample.manifest.json`: номера исходных строк,
  SHA-256 источника и результата, статистика покрытия.
- `scripts/prepare_audit_sample.py`: воспроизводимый отбор без внешних зависимостей.

Сначала гарантируется покрытие всех `verb`, HTTP-кодов и `stage`.
Затем жадный алгоритм выбирает записи с новыми признаками, придавая
больший вес редким: resource, subresource, apiGroup, состав вложенных полей,
отсутствие objectRef/annotations, query parameters и percent encoding в URI.
При равных оценках выбирается более ранняя исходная запись.
Итог отсортирован по исходным номерам строк; это не непрерывная последовательность.

В выборке представлены все 8 операций, коды 200/201/401/403/404/409/500/503,
обе стадии, 93 типа ресурсов, 2 записи без objectRef и 1 без annotations.
Выборка специально покрывает разнообразие и не воспроизводит частоты исходника.
Подходит для smoke tests парсинга, вложенного JSON, обработки пропусков,
URI, timestamps и идентификаторов. Не является benchmark качества модели
или набором для проверки непрерывных временных окон. Синтетические повреждённые
записи не добавлялись; код HTTP не интерпретируется как метка аномалии.

## Схема CSV

Все 15 исходных top-level полей сохранены с исходными именами.
Добавлен только `source_line` (номер строки исходника, начиная с 1).
Объекты и массивы (`user`, `sourceIPs`, `objectRef`, `responseStatus`,
`annotations`) сериализованы как JSON внутри CSV-ячейки.
Отсутствующее поле представлено пустой ячейкой; пустая строка и отсутствующее
поле поэтому неразличимы без обращения к исходнику.
Вложенные значения не очищены, не маскированы и не нормализованы.
Для чтения нужен CSV parser, а не split по запятой. При чтении CSV значения
будут строками; для объектов и массивов нужно применять `json.loads`.

Этот CSV сформирован непосредственно из raw logs и имеет заголовок.
Он отличается от авторского `audit-logs.csv` без заголовка: авторский файл
содержит выбранные плоские поля, а наша выборка сохраняет все исходные
top-level поля и вложенные структуры.

## Схема JSON и словарь полей

Файл имеет формат JSON-массива (`[{...}, {...}]`), а не JSON Lines.
Кодировка обоих файлов — UTF-8. JSON содержит 100 объектов.

| Поле | Тип в JSON | Назначение |
| --- | --- | --- |
| `source_line` | integer | Добавленный номер строки исходного raw log, начиная с 1 |
| `kind` | string | Тип audit объекта |
| `apiVersion` | string | Версия audit API |
| `level` | string | Уровень детализации аудита; в этом наборе `Metadata` |
| `auditID` | string | Идентификатор запроса; может объединять разные стадии |
| `stage` | string | Стадия обработки запроса |
| `requestURI` | string | URI вместе с query parameters |
| `verb` | string | Операция Kubernetes API |
| `user` | object | Идентификация пользователя и группы |
| `sourceIPs` | array | Список исходных IP |
| `userAgent` | string | Информация о клиенте |
| `objectRef` | object, необязательное | Ссылка на ресурс: namespace, имя, API group и другие поля |
| `responseStatus` | object | Код ответа и доступные сведения о результате |
| `requestReceivedTimestamp` | string | Время получения запроса; исходная точность сохранена |
| `stageTimestamp` | string | Время соответствующей стадии |
| `annotations` | object, необязательное | Дополнительные audit metadata |

В JSON отсутствие поля сохранено как отсутствие ключа, без подстановки `null`.
Набор не содержит `host`: это поле добавлялось при обработке Logstash
в авторском CSV и не присутствует в предоставленных raw events.

## Чтение выборок в Python

Примеры запускаются из корня проекта, внешние библиотеки не нужны.

### JSON

```python
import json
from pathlib import Path

path = Path("data/samples/audit-logs.sample.json")
events = json.loads(path.read_text(encoding="utf-8"))
assert len(events) == 100

for event in events:
    resource = event.get("objectRef", {}).get("resource")
    code = event["responseStatus"].get("code")
    print(event["source_line"], event["verb"], resource, code)
```

### CSV

```python
import csv
import json
from pathlib import Path

nested_fields = ("user", "sourceIPs", "objectRef", "responseStatus", "annotations")
path = Path("data/samples/audit-logs.sample.csv")

with path.open(encoding="utf-8", newline="") as stream:
    events = list(csv.DictReader(stream))

assert len(events) == 100
for event in events:
    event["source_line"] = int(event["source_line"])
    for field in nested_fields:
        if event[field] == "":
            del event[field]
        else:
            event[field] = json.loads(event[field])
```

Удаление пустых вложенных полей в примере соответствует этой конкретной
выборке; это не универсальное правило обработки произвольного CSV.

## Покрытие и сценарии тестирования

| Признак | Количество записей |
| --- | ---: |
| `list` / `create` / `get` | 82 / 8 / 4 |
| `watch` | 2 |
| `delete` / `patch` / `deletecollection` / `update` | По 1 |
| HTTP `200` / `201` | 77 / 6 |
| HTTP `401` / `403` / `404` | 1 / 2 / 10 |
| HTTP `409` / `500` / `503` | 1 / 2 / 1 |
| `ResponseStarted` / `ResponseComplete` | 3 / 97 |

Рекомендуемые проверки pipeline:

1. Загрузка 100 событий без потери первой записи и без разделения CSV по запятым вручную.
2. Декодирование вложенных объектов, массивов и кавычек в CSV.
3. Обработка отсутствующих `objectRef` и `annotations` без ошибки.
4. Разбор timestamp с сохранением UTC и микросекунд.
5. Разбор URI с query parameters и percent encoding без изменения исходного URI.
6. Сохранение `auditID`, `source_line` и исходных значений для трассировки преобразований.
7. Раздельная обработка `ResponseStarted` и `ResponseComplete`:
   разные стадии одного запроса не следует автоматически считать дубликатами.

Ожидаемые результаты конкретных нормализаций должен определить preprocessing
pipeline. В этой выборке нет целевых меток аномалий и исправленных версий событий.

## Повторный запуск

```bash
python3 scripts/prepare_audit_sample.py \
  --input /Users/freemax0602/Downloads/raw-audit-logs.log
```

После записи скрипт читает CSV обратно, проверяет количество записей
и совпадение каждого поля с исходным событием, включая вложенные JSON.
Проверки выполнены успешно. Исходный файл не изменён.
JSON также прочитан обратно: проверено совпадение всех событий с исходником
и соответствие номеров строк порядку записей в CSV.

Передача U2 не выполнялась: подготовлены локальные материалы.
Другие датасеты в рамках этого шага не добавлялись.

## Статус общей задачи

- [x] Подготовлена выборка из одного датасета в CSV и JSON.
- [x] Проверена читаемость файлов и соответствие исходным событиям.
- [x] Зафиксированы источник, формат, лицензия и ограничения.
- [ ] Довести каталог до минимум трёх проверенных датасетов.
- [ ] Передать U2 CSV, JSON и эту документацию до 06.11.2026.
- [ ] Подтвердить получение материалов U2.

Контрольные суммы и номера исходных строк находятся в
[manifest](../data/samples/audit-logs.sample.manifest.json).

