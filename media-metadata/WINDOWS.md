# Запуск на Windows

Пошагово, с нуля. Если Python уже стоит — сразу к шагу 3.

## 1. Поставить Python

Скачать с [python.org/downloads](https://www.python.org/downloads/) и при установке
**обязательно поставить галочку «Add python.exe to PATH»** на первом экране
установщика. Без неё команды из этой инструкции не найдутся.

Проверить, что получилось: нажать `Win+R`, набрать `cmd`, Enter, и в чёрном окне
выполнить:

```cmd
py --version
```

Должно ответить что-то вроде `Python 3.12.4`.

## 2. Скачать проект

Либо архивом: на странице репозитория **Code → Download ZIP**, распаковать,
например, в `C:\Users\Костя\mediameta`.

Либо через git, если он стоит:

```cmd
git clone https://github.com/orlasefrederic-lang/Lab C:\Users\%USERNAME%\Lab
```

Нужная папка внутри — `media-metadata`.

## 3. Установить

Зайти в папку `media-metadata` и **дважды кликнуть `install-windows.bat`**.
Он сам найдёт Python, поставит библиотеку и её зависимости, скачает exiftool
(для HEIC с айфона, RAW, MKV и AVI) и в конце покажет версию. Окно закроется
по нажатию клавиши.

Если предпочитаешь руками:

```cmd
cd C:\Users\%USERNAME%\Lab\media-metadata
py -m pip install -e .
py -m mediameta exiftool install
```

## 4. Пользоваться

### Мышкой, без командной строки

В папке проекта лежат два файла — на них можно просто **перетаскивать фото и видео**:

* **`Показать метаданные.bat`** — откроет окно и покажет всё, что есть в файле.
* **`Удалить метаданные (копия).bat`** — сделает рядом копию с пометкой `_clean`
  в имени, без геолокации, модели камеры и дат. Оригинал не трогается.

Перетаскивать можно сразу несколько файлов.

### Из командной строки

Открыть командную строку прямо в нужной папке: зайти в папку с фото в Проводнике,
нажать `Shift` + правая кнопка мыши на пустом месте → «Открыть окно PowerShell здесь»
(или набрать `cmd` в адресной строке Проводника и нажать Enter).

```cmd
mediameta show photo.jpg
mediameta show "C:\Users\Костя\Pictures\отпуск\IMG_0042.jpg"
mediameta set photo.jpg -s title="Закат" -s artist="Костя"
```

Пути с пробелами и кириллицей — в двойных кавычках.

Если Windows отвечает «mediameta не является внутренней или внешней командой»,
значит папка со скриптами Python не в `PATH`. Ничего страшного, тот же вызов
работает через Python:

```cmd
py -m mediameta show photo.jpg
```

## Частые задачи

```cmd
:: посмотреть всё, что есть в файле
mediameta show IMG_0042.jpg

:: снять геометки перед тем, как выложить фото
mediameta remove IMG_0042.jpg -f gps_latitude -f gps_longitude

:: вычистить вообще все метаданные
mediameta remove IMG_0042.jpg --all --backup

:: проставить дату съёмки и координаты
mediameta set IMG_0042.jpg -s "date=2024-07-01 18:30" -s gps=55.7558,37.6176

:: подписать все фото в папке и во вложенных папках
mediameta set "C:\Users\Костя\Pictures\отпуск" -r -s artist="Костя" -s keywords="море,лето"

:: все jpg в текущей папке (звёздочку раскрывает сама программа)
mediameta set *.jpg -s copyright="(c) 2024 Kostya"

:: выгрузить метаданные папки в файл
mediameta show "C:\Users\Костя\Pictures" -r --json > meta.json

:: посмотреть, что изменится, ничего не трогая
mediameta set *.jpg -s rating=5 --dry-run
```

Флаг `--backup` сохраняет оригинал рядом как `ФАЙЛ.bak` — полезно, пока
не привык. Флаг `-o ДРУГОЙ_ФАЙЛ` пишет результат в новый файл, оставляя
исходный как есть.

## Если что-то пошло не так

| Что видно | Что делать |
|---|---|
| `mediameta не является внутренней или внешней командой` | Запускать как `py -m mediameta …`, либо переустановить с галочкой «Add python.exe to PATH» |
| `py не является внутренней или внешней командой` | Python не установлен или без галочки PATH — вернуться к шагу 1 |
| Вместо русских букв кракозябры | Выполнить в том же окне `chcp 65001` и повторить команду |
| `is locked by another program` | Файл открыт в просмотрщике или редакторе — закрыть его и повторить |
| `no files matched` | Проверить путь; если в нём пробелы или кириллица — взять в двойные кавычки |
| `not a format mediameta handles natively` или `exiftool is not installed` | Формат (HEIC, RAW, MKV, AVI) требует exiftool: выполнить `mediameta exiftool install` |
| `could not download https://exiftool.org/...` | Нет доступа к exiftool.org (интернет, VPN, антивирус) — повторить позже или поставить вручную, см. ниже |
| `Отказано в доступе` при установке | Запустить `install-windows.bat` правой кнопкой → «Запуск от имени администратора» |

## exiftool: HEIC, RAW, MKV, AVI

Родные бэкенды покрывают JPEG, PNG, WebP, MP4, MOV, M4A. Для HEIC с айфона,
RAW с зеркалки, MKV и AVI нужен exiftool. `install-windows.bat` скачивает его
сам; если установка шла руками или exiftool тогда не скачался:

```cmd
mediameta exiftool install
```

Команда берёт свежую официальную сборку с [exiftool.org](https://exiftool.org/),
сверяет её SHA-256 с контрольной суммой, опубликованной там же, и кладёт в
`%LOCALAPPDATA%\mediameta\exiftool`. Ни `PATH`, ни права администратора не
нужны, а дальше mediameta подхватывает её сама.

```cmd
mediameta exiftool status    :: какой exiftool используется и откуда
mediameta exiftool install   :: обновить до последней версии
mediameta exiftool remove    :: удалить свою копию
```

Если exiftool у тебя уже стоит отдельно, mediameta найдёт и его — через
`PATH` или переменную окружения `MEDIAMETA_EXIFTOOL` с полным путём к
`exiftool.exe`. Своя скачанная копия при этом в приоритете.

## Обновить до свежей версии

```cmd
cd C:\Users\%USERNAME%\Lab
git pull
```

Устанавливали через `pip install -e .`, поэтому переустанавливать после
обновления не надо — изменения подхватываются сразу.
