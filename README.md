# C/C++ SCA — установка, скачивание исходников, создание базы и проверка

Этот проект содержит **реальный сканер `cpluschecks`** и оркестратор `run_all_checkers.py`. Оркестратор последовательно:

1. Читает `PRODUCT` и `LINK_SOURCE` из Python-чекеров.
2. Скачивает доступные репозитории в каталог эталонных исходников.
3. Строит базу `fingerprints.sqlite` из загруженных исходников.
4. Проверяет целостность SQLite и запускает сканер для каждого доступного продукта.
5. Создаёт отчёт по оригиналу, копии с изменениями и отрицательному контролю.

**На данном этапе проверяем только наличие продукта в исходном коде. Точность его версии не оцениваем.**

## 1. Требования и установка на Debian / Kali

Понадобятся Linux, Python 3.11+, Git, свободное место на диске и сеть для Git-клонирования. При скачивании всех источников объём данных может быть значительным: заранее проверьте `df -h`.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git unzip
mkdir -p ~/cpp-sca-test
cd ~/cpp-sca-test
unzip /путь/к/cpp_all_checkers_pipeline.zip
cd cpp_product_detection_bundle

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ./cpluschecks
python3 run_all_checkers.py --help
```

Все следующие команды запускаются **из `cpp_product_detection_bundle`** и с активированным окружением `.venv`. После нового входа в терминал вновь выполните `source .venv/bin/activate`.

## 2. Проверить перечень чекеров и адресов источников

```bash
python3 run_all_checkers.py --dry-run --workdir ./all_checker_work
```

Команда ничего не клонирует и не создаёт базу. Она показывает продукты и адреса источников, которые удалось извлечь из констант `LINK_SOURCE` в чекерах. Список также записывается в `all_checker_work/reports/checker_manifest.json`.

**Ограничение:** чекеры без буквального `LINK_SOURCE`, динамически вычисляемые URL или ошибки разбора попадают в `warnings`, а не автоматически скачиваются. Таким образом, количество обнаруженных репозиториев **не равно** числу всех поддерживаемых чекеров.

## 3. Запустить полный процесс

```bash
python3 run_all_checkers.py \
  --workdir ./all_checker_work \
  --workers 2 \
  --threads 2
```

Это основной запуск. Делать отдельные `git clone`, запускать `build_fingerprint_index.py` вручную и вызывать сканер по одному продукту **не требуется**.

Параметры:
- `--workdir` — рабочий каталог исходников, базы и отчётов;
- `--workers` — число параллельных операций скачивания;
- `--threads` — число потоков сканера;
- `--limit N` — проверить только первые N доступных продуктов **после скачивания и построения базы по всем доступным**;
- `--modify 0.30` — добавить комментарий в выбранные 30% C/C++ файлов;
- `--update` — обновить уже скачанные исходники (может изменить воспроизводимость);
- `--skip-download` — использовать исходники, уже имеющиеся в каталоге;
- `--skip-build` — использовать существующую базу, не перестраивая её;
- `--db /absolute/path/fingerprints.sqlite` — указать расположение базы.

**Важно:** скрипт скачивает текущие HEAD-ветки, не все версии продуктов. Это контроль работы детектора, но не проверка покрытия релизов.

### Как запустить сначала 3 теста, не сокращая скачивание

```bash
python3 run_all_checkers.py \
  --workdir ./all_checker_work \
  --workers 2 --threads 2 --limit 3
```

Этот вариант всё равно скачает все доступные репозитории и построит полную базу. Для экономии места сперва изучите `--dry-run`, затем при необходимости ограничьте корпус вручную или доработайте этап скачивания.

## 4. Где находится база фингерпринтов

После успешного этапа сборки:

```text
all_checker_work/
├── catalog/
│   ├── <product_1>/reference/...
│   └── <product_2>/reference/...
├── fingerprints.sqlite
├── mutated/
├── negative/
└── reports/
```

Эталонная структура — `catalog/<product>/reference/<файлы Git-репозитория>`. `reference` здесь просто метка текущего скачанного снимка, а **не версия продукта**.

Проверка SQLite:

```bash
ls -lh all_checker_work/fingerprints.sqlite
python3 - <<'PY'
import sqlite3
db = sqlite3.connect("all_checker_work/fingerprints.sqlite")
print("SQLite integrity:", db.execute("PRAGMA integrity_check").fetchone()[0])
print("Tables:", [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")])
db.close()
PY
```

Ожидаемый ответ по целостности — `ok`. Наличие таблиц и целостность базы **не доказывают**, что все продукты корректно индексированы.

### Пересобрать базу отдельно

Если код уже скачан, но нужно создать SQLite заново:

```bash
python3 cpluschecks/build_fingerprint_index.py \
  ./all_checker_work/catalog \
  --db ./all_checker_work/fingerprints.sqlite
```

Перед перезаписью нужной базы сделайте копию:

```bash
cp all_checker_work/fingerprints.sqlite all_checker_work/fingerprints.backup.sqlite
```

## 5. Повторный запуск без скачивания и построения базы

```bash
python3 run_all_checkers.py \
  --workdir ./all_checker_work \
  --skip-download --skip-build --limit 5
```

С собственной базой:

```bash
python3 run_all_checkers.py \
  --workdir ./all_checker_work \
  --skip-download --skip-build \
  --db /путь/к/fingerprints.sqlite --limit 5
```

Используйте только совместимую с текущим сканером базу. Пересборка нужна, если сменились формат БД, корпус эталонов или алгоритм фингерпринтов.

## 6. Какие проверки выполняются

| Сценарий | Проверяем | Успех |
|---|---|---|
| `original` | Исходный репозиторий, использованный для построения БД | Подтверждён продукт |
| `comment_modified` | Копия с добавленными комментариями в части C/C++ файлов | Подтверждён продукт |
| `negative_no_source` | `dummy.cpp` и имя продукта в комментарии CMake, без его исходников | Нет подтверждённого совпадения по хешу |

Подтверждением детектор считает компонент со свойством `detection.identity_confirmed=true`, у которого в `detection.identity_methods` есть `hash:`. Простое упоминание имени библиотеки в CMake недостаточно.

Сценарий `comment_modified` **не изменяет 30% строк, функций или логики**: он дописывает комментарий к выбранным файлам. Это ограниченный регрессионный тест.

**Важно о точности:** положительные исходники участвуют и в обучающем каталоге, и в проверке. Следовательно, полученные проценты — *in-sample контроль и регрессия*, **не независимый Recall/Precision**. Для реальной проверки нужны сторонние проекты и изменённые копии, **не добавленные заранее в базу**.

## 7. Где искать результаты

```text
all_checker_work/reports/
├── checker_manifest.json   # список источников и предупреждения
├── downloads.json          # отчёт загрузчика
├── missing_sources.json    # нескачанные репозитории
├── db_validation.json      # integrity_check, список таблиц и размер базы
├── download.log            # ошибки Git / скачивания
├── build.log               # журнал построения базы
├── product_detection.csv   # результат для каждого продукта / сценария
├── summary.json            # агрегированные числа
├── sboms/                  # known, unknown и объединённые CycloneDX JSON
└── logs/                   # отдельные журналы вызовов сканера
```

Просмотр сводки:

```bash
python3 -m json.tool all_checker_work/reports/summary.json | less
```

Показать ошибки и пропуски в CSV:

```bash
python3 - <<'PY'
import csv
p = "all_checker_work/reports/product_detection.csv"
with open(p, encoding="utf-8", newline="") as f:
    for row in csv.DictReader(f):
        if row["status"] != "PASS":
            print(row["product"], row["scenario"], row["status"], row.get("error",""))
PY
```

Статусы:
- `PASS` — ожидание сценария выполнено;
- `MISS` — ожидаемый продукт не обнаружен в положительном сценарии;
- `FALSE_POSITIVE` — продукт подтверждён по хешам в простом отрицательном сценарии;
- `SCAN_ERROR` — сканер не отработал или не удалось прочесть SBOM;
- `ERROR` — не удалось подготовить тестовую копию.

Поле `other_products` — дополнительные найденные имена. Это **не автоматически ложные срабатывания**: репозиторий может содержать вложенные исходники других библиотек.

## 8. Если что-то пошло не так

**`ModuleNotFoundError` / нет команды `cxx-sca`:** активируйте `.venv`, повторите `python3 -m pip install -e ./cpluschecks`.

**Не клонируется часть Git-репозиториев:** проверьте сеть, Git, `reports/download.log` и `reports/missing_sources.json`. Скрипт продолжит работать с доступными источниками, но общий запуск может завершиться кодом `1`.

**Нет базы `fingerprints.sqlite`:** откройте `reports/build.log`; если сборка не закончилась успешно, результаты обнаружения нельзя интерпретировать.

**Результат `MISS`:** откройте соответствующие `reports/sboms/*.known.json`, `*.unknown.json` и журнал из `reports/logs/`. Проверьте совпадение имени продукта, исходные файлы и `detection.identity_methods`.

**Не хватает места:** проверьте `df -h` и `du -sh all_checker_work/*`; используйте выделенный большой раздел. Повторный запуск с `--skip-download --skip-build` не загружает и не пересоздаёт базу.

**Код возврата `1`:** не всегда означает поломку сканера. Он бывает при отсутствующих источниках и неуспешных сценариях. Смотрите `summary.json`, CSV и журналы.

## 9. Как понять, что всё действительно завершено

Проверить **все четыре вещи**:

1. `reports/missing_sources.json` — какие продукты остались без исходников;
2. `reports/db_validation.json` — `integrity` равно `ok`;
3. `reports/product_detection.csv` — конкретные `MISS`, `FALSE_POSITIVE`, `SCAN_ERROR`;
4. `reports/summary.json` — долю пройденных тестов по сценариям.

Если все доступные продукты проходят тесты, корректный вывод: **сканер узнаёт загруженные эталонные проекты и их копии с комментариями по хешовым доказательствам**. Утверждать, что он безошибочно определяет любой изменённый сторонний C/C++ продукт, по такому запуску ещё нельзя.
