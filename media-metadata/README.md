# mediameta

Чтение и редактирование метаданных фото и видео — из командной строки и из Python.

Один и тот же набор полей (`title`, `artist`, `datetime_original`, `gps_latitude`, …)
работает и для JPEG, и для MP4: библиотека сама раскладывает их по EXIF-тегам,
текстовым чанкам PNG или атомам QuickTime.

```console
$ mediameta show IMG_0042.jpg
IMG_0042.jpg
  JPEG · image · backend=exif
  metadata:
    title                  Закат на заливе
    artist                 Костя
    datetime_original      2024-07-01 18:30:00
    camera_make            Canon
    camera_model           EOS R6
    gps_latitude           55.7558
    gps_longitude          37.6176
    width                  6000
    height                 4000

$ mediameta set IMG_0042.jpg -s title="Закат" -s gps=55.7558,37.6176 --backup
IMG_0042.jpg: updated title, gps_latitude, gps_longitude
```

## Установка

```bash
cd media-metadata
pip install -e .
```

**Windows:** есть отдельная пошаговая инструкция — [WINDOWS.md](WINDOWS.md).
Коротко: поставить Python с галочкой «Add python.exe to PATH», затем дважды
кликнуть `install-windows.bat`. Для работы без командной строки в папке лежат
`Показать метаданные.bat` и `Удалить метаданные (копия).bat` — на них можно
просто перетаскивать файлы мышкой.

Зависимости: `piexif` и `pillow` (ставятся автоматически). Внешние программы
не нужны — MP4/MOV разбирает собственный парсер контейнера.

Необязательно: установленный `exiftool` автоматически подключается как
дополнительный бэкенд и добавляет форматы, которых нет в чистом Python
(HEIC, RAW, MKV, AVI, запись в TIFF):

```bash
sudo apt install libimage-exiftool-perl   # или: brew install exiftool
```

## Команды

| Команда | Что делает |
|---|---|
| `mediameta show ФАЙЛ…` | показать метаданные (`--json`, `--raw`, `-f поле`) |
| `mediameta set ФАЙЛ…` | записать или удалить поля (`-s поле=значение`) |
| `mediameta remove ФАЙЛ…` | удалить отдельные поля (`-f`) или всё (`--all`) |
| `mediameta copy ИСТОЧНИК ПРИЁМНИК` | перенести метаданные между файлами |
| `mediameta fields` | список полей и их псевдонимов |
| `mediameta backends` | какие бэкенды доступны в системе |

Общие флаги: `-r` (рекурсивно по папкам), `--backend`, `--backup`,
`-o/--output` (писать в другой файл), `-n/--dry-run`.

### Примеры

```bash
# Посмотреть всю папку и выгрузить в JSON
mediameta show ~/Фото -r --json > meta.json

# Проставить дату съёмки и координаты
mediameta set photo.jpg -s "date=2024-07-01 18:30" -s gps=55.7558,37.6176,140

# Координаты можно писать и в градусах-минутах-секундах
mediameta set photo.jpg -s "lat=55 deg 45' 20.9\" N" -s "lon=37°37'3.36\"E"

# Подписать все видео в папке одним автором, сохранив оригиналы
mediameta set ~/Видео -r -s artist="Костя" -s keywords="отпуск,море" --backup

# Убрать геолокацию перед публикацией
mediameta remove photo.jpg -f gps_latitude -f gps_longitude

# Снести вообще все метаданные (EXIF, XMP, IPTC, комментарии)
mediameta remove photo.jpg --all

# Перенести метаданные с оригинала на отредактированную копию
mediameta copy original.jpg edited.jpg

# Посмотреть, что изменится, ничего не трогая
mediameta set photo.jpg -s rating=5 --dry-run

# Шаблоны раскрываются самой программой — удобно в командной строке Windows,
# где оболочка этого не делает
mediameta set *.jpg -s copyright="(c) 2024 Kostya"

# Редкий тег напрямую, мимо канонических полей
mediameta set photo.jpg -t EXIF:ISOSpeedRatings=400
mediameta set clip.mp4 -t "iTunes:©wrt=Костя"
```

Пустое значение удаляет поле: `mediameta set photo.jpg -s title=`.

## Python API

```python
from mediameta import read_metadata, write_metadata, remove_metadata, copy_metadata

record = read_metadata("clip.mp4")
print(record.common["duration"], record.common["gps_latitude"])
print(record.raw["QuickTime:com.apple.quicktime.model"])
print(record.to_json())

write_metadata("clip.mp4", {
    "title": "Лето 2024",
    "artist": "Костя",
    "keywords": ["море", "отпуск"],
    "datetime_original": "2024-07-01 10:00",   # строки разбираются автоматически
    "gps_latitude": 55.7558,
    "gps_longitude": 37.6176,
})

write_metadata("photo.jpg", {"title": None})          # удалить одно поле
remove_metadata("photo.jpg", ["gps_latitude"])        # то же самое, явнее
remove_metadata("photo.jpg")                          # вычистить всё
copy_metadata("original.jpg", "edited.jpg")           # перенести между файлами
```

`MetadataRecord.common` — канонические поля с нормальными типами Python
(`datetime`, `float`, `list`), `MetadataRecord.raw` — всё, что нашёл бэкенд,
с исходными именами тегов.

## Форматы

| Формат | Чтение | Запись | Бэкенд |
|---|---|---|---|
| JPEG, WebP | да | да | `exif` (piexif) |
| PNG | да | да | `png` (Pillow + piexif) |
| MP4, M4V, M4A, MOV, 3GP | да | да | `mp4` (собственный парсер) |
| TIFF | да | только с exiftool | `exif` / `exiftool` |
| HEIC, AVIF, RAW (CR2/NEF/ARW/DNG…), MKV, AVI, MP3, FLAC | только с exiftool | только с exiftool | `exiftool` |

Бэкенд выбирается автоматически: сначала родной (без внешних программ),
`exiftool` подключается там, где родной не справляется. Можно задать явно:
`--backend exiftool` или `--backend native`.

Формат определяется по содержимому файла, а не только по имени: файл без
расширения (`IMG_0001`) обрабатывается нормально, а JPEG, по ошибке
названный `.png`, не будет перекодирован в PNG.

## Куда именно пишутся поля

* **JPEG/WebP** — EXIF: `Artist`, `Copyright`, `Make`, `Model`, `Software`,
  `ImageDescription`, `DateTimeOriginal`/`DateTimeDigitized`/`DateTime`,
  `Orientation`, `Rating`, GPS IFD; заголовок, комментарий и ключевые слова —
  в `XPTitle`/`UserComment`/`XPKeywords` (их понимают Проводник Windows,
  exiftool, большинство просмотрщиков).
* **PNG** — текстовые чанки `Title`, `Author`, `Description`, `Copyright`,
  `Creation Time`, `Keywords` плюс полноценный блок `eXIf` для GPS, камеры и
  рейтинга.
* **MP4/MOV** — атомы `moov/udta/meta/ilst` в стиле iTunes (`©nam`, `©ART`,
  `desc`, `cprt`…), координаты в `moov/udta/©xyz` в формате ISO 6709, а если
  в файле уже есть ключи Apple (`com.apple.quicktime.*`, как в видео с
  iPhone) — они обновляются синхронно, чтобы значения не разошлись.
  Дата съёмки заодно проставляется в заголовки `mvhd`/`tkhd`/`mdhd`.

XMP читается (в том числе то, что оставили Lightroom или Photoshop), но не
записывается — для записи XMP поставьте `exiftool`.

## Безопасность данных

Редактирование метаданных не должно портить файлы, поэтому:

* запись всегда идёт во временный файл рядом и заменяет оригинал атомарно —
  сбой на полпути оставляет исходный файл нетронутым;
* `--backup` сохраняет оригинал как `ФАЙЛ.bak` (существующие резервные копии
  не перетираются);
* пиксели и звук не перекодируются — меняются только блоки метаданных;
* для MP4 пересчитываются смещения чанков (`stco`/`co64`), если `moov`
  меняет размер и сдвигает `mdat`; если рядом с `moov` есть свободное место
  (`free`), правка укладывается в него и данные вообще не двигаются.
  Фрагментированные MP4 (`moof`) не изменяются «на месте» — для них нужен
  `--output` или `exiftool`.

## Тесты

```bash
pip install -e ".[dev]"
python -m pytest -q
```

141 тест: разбор координат и дат, полный цикл записи/чтения для JPEG, WebP,
PNG и MP4, поведение CLI, отказоустойчивость (битый файл, нет прав, чужой
формат). Отдельно проверяется, что после правки тегов в MP4 данные по
смещениям `stco` остаются на месте — во всех трёх раскладках контейнера
(`mdat` первым, `moov` первым, с `free`-подушкой). Если в системе есть
`exiftool` или `mutagen`, дополнительно сверяется, что записанное этой
библиотекой они читают так же.

## Ограничения

* Запись XMP и IPTC — только через `exiftool`.
* TIFF, HEIC, RAW, MKV, AVI читаются/пишутся только с `exiftool`.
* PNG при записи пересобирается Pillow: изображение не меняется (формат
  без потерь), но нестандартные вспомогательные чанки могут не сохраниться.
* Фрагментированные MP4 правятся только с `--output`.
