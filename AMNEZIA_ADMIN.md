# Экспериментальное управление peer Amnezia AWG2 и WireGuard

Модуль `sovagrid_vpn.amnezia_admin` — отдельная административная команда.
Она не запускается из обычного `run.sh`. Отдельный opt-in Unix-broker
подготовлен в исходниках; управление каждым типом контейнера включается
независимо. Панель пока показывает действия AWG2, а WireGuard API Agent
подготовлен для следующего пакетного обновления клиентов. Проверки записи
проводились только в одноразовых контейнерах с синтетическими ключами.

Для **нового** AmneziaWG 3.1 контейнера есть отдельный root-only установщик
`sovagrid_vpn.amnezia_provision`, описанный в [README](README.md#новый-сервер-amneziawg-31).
Он собирает совместимый сервер из закреплённого официального базового образа,
который сам по себе не является готовым VPN-сервером. Модуль управления
дополнительно принимает его точную immutable-ссылку в Docker `Config.Image`,
но по-прежнему закрепляет container ID и image ID и проверяет все файлы и
работающий `awg0`. Установленный в режиме `split` контейнер не выдаёт через
SovaGrid клиентский профиль с маршрутом `full`.

## Область действия и требования

- Ubuntu/Linux, Python 3.10+, `python3-cryptography`, Docker CLI и Docker daemon; внутри контейнера
  должны быть `bash`, `stat`, `head`, `mktemp`, `mv`, `awg`/`wg` и
  `awg-quick`/`wg-quick`.
- Запускать непосредственно от root из каталога репозитория. Код не принимает
  произвольные пути, имена Docker-контейнеров, команды или Docker flags.
- Поддерживаются только фиксированные цели `awg2` → `amnezia-awg2`, `awg0`
  и `wireguard` → `amnezia-wireguard`, `wg0`. Для обеих фиксированы пути
  сервера, `clientsTable` и общего PSK под `/opt/amnezia/`.
- Контейнер должен работать с ожидаемым именем и исходным образом. При
  `enroll` сохраняются точные Docker container ID и image ID; последующая
  замена контейнера блокирует запись. Bind/volume mount над конфигом,
  `clientsTable` или PSK блокирует принятие под управление.
- Серверный конфиг, реестр, общий PSK и работающий интерфейс обязаны быть
  согласованы. Поддержан один IPv4 `Address`, один `ListenPort`, peer с одним
  `AllowedIPs = x.x.x.x/32` в этой подсети и единым PSK. Неизвестный формат,
  дубли и неработающий интерфейс дают отказ. Проверка прав файлов не допускает
  открытого для всех приватного ключа и сохраняет разрешённые режимы при замене.

## Команды

Команды выполняются из каталога `sovagrid-vpn`:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m sovagrid_vpn.amnezia_admin status awg2
```

После `enroll` доступен локальный предпросмотр настроек без записи в контейнер:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m sovagrid_vpn.amnezia_admin settings-preview awg2
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m sovagrid_vpn.amnezia_admin settings-preview wireguard
```

Он требует точного прежнего container/image ID, совпадения SHA-256 конфига и
реестра с закреплённым состоянием, согласованности runtime и отсутствия
незавершённой операции. JSON содержит эти идентификаторы и хеши, поколение,
протокол, интерфейс, порт прослушивания, серверный IPv4 и подсеть, число
клиентов, а для AWG — только проверенные числовые `Jc/Jmin/Jmax`, `S1–S4`,
`H1–H4`. Поле `header_protection_key_present` показывает лишь наличие ключа;
сам ключ, приватный ключ сервера, PSK, имена и публичные ключи клиентов, их
адреса и исходный конфиг не выдаются. `listen_port` — порт процесса внутри
контейнера, а не гарантия открытого порта Docker или firewall. `awg_parameters`
прочитаны из закреплённого файла: `awg show dump` не сообщает их, поэтому
`awg_parameters_runtime_verified=false`. Runtime проверяется для ключа и порта
интерфейса и полного набора peer с PSK и адресами. Ответ ограничен 4096 байтами.

`apply_supported=false` в одном `settings-preview` означает, что числовые
параметры работающего интерфейса ещё не сверены; пригодность к записи
определяет отдельный `settings-plan`. По [официальному FAQ Amnezia](https://docs.amnezia.org/faq/)
смена настроек протокола или порта сервера делает ранее выданные клиентские
конфигурации непригодными. Без атомарного перевыпуска и доставки **всех**
клиентских профилей, а для порта ещё и согласованного изменения публикации
Docker/сетевых правил, безопасный `apply` для сервера с клиентами невозможен.
После явного включения отдельного broker `settings-preview` доступен
администратору через Agent, Hub и Web; каждое звено повторно проверяет точную
форму ответа.

Для будущего графического мастера добавлен `settings-plan awg2`: он принимает
SHA-256 конфига и поколение из `settings-preview`, а также JSON с одним или
несколькими изменяемыми числовыми полями `Jc/Jmin/Jmax`, `S1–S4`, `H1–H4`.
План повторно сверяет контейнер, конфиг, реестр и runtime под блокировкой.
Для AWG 3.1 он дополнительно читает работающие `Jc/Jmin/Jmax`, `S1–S4`,
`H1–H4` через фиксированные селекторы `awg show awg0 ...` и сравнивает их с
закреплённым файлом. `HeaderProtectionKey` считывается и сравнивается только в
памяти root-процесса: его значение не включается в JSON, аргументы команд,
ошибки или журналы. Если установленный `awg` не поддерживает селектор либо
работающий интерфейс отличается, план отказывается без записи. Наличие этих
селекторов подтверждено [исходным кодом официального amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools/blob/master/src/show.c);
это не доказывает, что уже запущенная версия контейнера поддерживает их.
При включённом Header Protection план также отказывается от предполагаемых
`S1–S4` меньше 12 байт: этот минимум указан в
[официальном описании AmneziaWG 3](https://github.com/amnezia-vpn/amneziawg-go/blob/master/README.md).
После проверки план строит **только в памяти** предполагаемый конфиг. В ответе
есть точные изменённые поля и SHA-256 предполагаемого конфига без ключей или
адресов клиентов. Смена исходного SHA или поколения возвращает отказ.
`apply_supported` в плане равно `true` только при нуле клиентов и успешной
проверке всех числовых параметров и Header Protection в работающем AWG3.
Если клиенты есть, ответ содержит `apply_supported=false` и
`CLIENT_PROFILES_REQUIRE_REISSUE`. Неподдерживаемый селектор AWG приводит к
отказу без плана. Сам план ничего не пишет в контейнер.

Для тестового AWG3-сервера **без единого клиента** добавлен отдельный root-only
`settings-apply`: он принимает SHA-256 исходного конфига, поколение, SHA-256
предполагаемого конфига из `settings-plan` и тот же JSON с числовыми полями.
Под блокировкой он повторяет план и отвергает любое изменение container/image,
реестра, конфигурации, поколения, runtime и ранее одобренного результата.
`ListenPort`, адреса, ключи и заголовочный ключ менять нельзя. Перед записью
создаётся durable-журнал с исходным и предполагаемым конфигом; после
`syncconf` каждый числовой селектор и заголовочный ключ сравниваются с
предполагаемыми значениями. При расхождении транзакция возвращает старый
конфиг и проверяет его работающие параметры. Восстановление после обрыва
принимает только старые или предполагаемые runtime-параметры, иначе
останавливается без перезаписи. Для панели эта же транзакция доступна через
отдельно включаемый root Unix broker с двухшаговым подтверждением. Она не
применяется на сервере с действующими клиентами.

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m sovagrid_vpn.amnezia_admin \
  settings-apply awg2 OLD_CONFIG_SHA256 GENERATION PROPOSED_CONFIG_SHA256 \
  '{"Jc":"5"}'
```

Для будущего изменения нужен отдельный план миграции, а не запись нового
значения в `awg0.conf`: (1) закрепить ожидаемые container/image ID,
SHA-256 конфига/реестра, runtime-состав peer и опубликованные порты как CAS;
(2) учесть **все** профили, включая клиентов вне SovaGrid, и подготовить
новые зашифрованные конфиги; (3) поднять новый listener параллельно старому,
проверить handshake новым профилем, доставить профили и только затем
переключить клиентов; (4) сохранить старый listener на время отката и
запретить удаление до подтверждённого перехода. Нужны fault-injection тесты
для каждого этапа и реальная проверка обеих версий AmneziaWG. Текущий
одноконтейнерный `syncconf` не обеспечивает такой переход.

Перед первым принятием команда `enroll-preview` проверяет точный контейнер,
конфигурацию, реестр и runtime, затем возвращает ограниченный JSON без ключей,
имён и адресов клиентов. Его поля `container_id`, `image_id`,
`config_sha256` и `table_sha256` можно передать обратно при подтверждении:
`enroll` повторно сверит все четыре значения под блокировкой. Это контракт
для графического мастера; сам мастер ещё не выпущен. Команда создаёт только
локальный root-owned файл состояния и не меняет серверный конфиг:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m sovagrid_vpn.amnezia_admin enroll-preview awg2
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m sovagrid_vpn.amnezia_admin \
  enroll awg2 --confirm-container-id ID_FROM_PREVIEW \
  --confirm-image-id IMAGE_FROM_PREVIEW \
  --confirm-config-sha256 CONFIG_SHA256_FROM_PREVIEW \
  --confirm-table-sha256 TABLE_SHA256_FROM_PREVIEW
```

Для ручной установки прежний `enroll ... --confirm-container-id` остаётся
доступен после отдельной сверки полного ID через Docker. Частичный набор
хешей preview команда отвергает. Если состояние контейнера изменилось между
просмотром и подтверждением, запись не производится; нужно запросить новый
preview. Клиенты вне SovaGrid при принятии не изменяются.

Для AWG3 и стандартного WireGuard команда сама создаёт ключевую пару клиента и выдаёт профиль
только зашифрованным. `RECIPIENT_P256_PUBLIC_B64URL` генерируется в браузере
или приложении как открытая точка P-256; закрытый ключ расшифрования остаётся
там. `ENDPOINT_HOST` — публичный IP или DNS сервера, порт берётся из текущего
конфига. Для `create-profile` вместо ручного адреса можно передать `auto`:
сервер выберет первый свободный IPv4 из своей подсети под блокировкой
конфигурации. Адреса сервера, сети, broadcast и всех существующих peer
исключаются. Если свободного адреса нет, команда откажет без записи. Явный
адрес по-прежнему доступен:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m sovagrid_vpn.amnezia_admin \
  create-profile awg2 iphone auto vpn.example.com RECIPIENT_P256_PUBLIC_B64URL
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m sovagrid_vpn.amnezia_admin \
  sealed-export awg2 iphone RECIPIENT_P256_PUBLIC_B64URL
# Для принятого под управление стандартного WireGuard контейнера:
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m sovagrid_vpn.amnezia_admin \
  create-profile wireguard iphone auto vpn.example.com RECIPIENT_P256_PUBLIC_B64URL
```

По умолчанию `--route split`: профиль направляет через туннель только
серверную VPN-подсеть. `--route full` ставит для AWG3
`AllowedIPs = 0.0.0.0/0, ::/0` для обеих целей,
но CLI не включает forwarding, NAT, IPv6 или firewall; их нужно проверять
отдельно. `create-profile` выдаёт `profile_format=awg3-conf` или `wg-conf` и вложенный
`sealed_profile`. Последующий `sealed-export` выдаёт **только** конверт
`{version:1,ephemeral_public_key,salt,nonce,ciphertext}`. Для него
используется тот же ECDH P-256 → HKDF-SHA256 → AES-256-GCM, что и для
управляемого SovaGrid WireGuard, с AAD
`SovaGrid profile\0TARGET\0CLIENT`, где TARGET — `awg2` или `wireguard`.
Сервер хранит закрытый ключ клиента только
в root-owned состоянии и при экспорте заново строит профиль, сверяя хеш и
живые параметры. Текст `.conf` не входит в JSON, stderr или argv.

Для уже подготовленного **внешнего** профиля остаётся отдельная команда
`add`: она требует готового публичного ключа клиента и свободного IPv4:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m sovagrid_vpn.amnezia_admin \
  add awg2 iphone CLIENT_PUBLIC_KEY_BASE64 10.44.0.3
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m sovagrid_vpn.amnezia_admin \
  revoke awg2 iphone
```

`CLIENT_PUBLIC_KEY_BASE64` — обычный WireGuard/AmneziaWG X25519 public key:
ровно 32 байта в каноническом base64 с `=`. Не передавайте сюда private key.
Имя клиента: ASCII `a-z`, затем до 31 символа `a-z`, `0-9`, `_`, `-`.
Адрес указывается без `/32`. Команда не выбирает адрес сама, чтобы перед
записью его можно было сверить с существующими peer. `revoke` принимает
только клиента, ранее добавленного этим модулем и сохранённого в его
root-owned состоянии. Удаление по одному лишь совпадению имени запрещено.
SovaGrid управляет не более чем 128 клиентами каждого target: этот предел
совпадает с размером списка `owned_clients`, принимаемым Agent и Hub.

Все успешные команды возвращают одну строку JSON. `add`/`revoke` возвращают
`target`, `action`, `client`, `configured_clients`, `cleanup_required`.
`create-profile` возвращает те же поля и `profile_format`, `sealed_profile`.
`sealed-export` возвращает только пять полей конверта.
`enroll-preview` возвращает закрепляемые ID/хеши, протокол, интерфейс, порт,
подсеть и только число клиентов. `status` возвращает `target`, `enrolled`, `recovery_required`,
`owned_clients`. `enroll` возвращает `target`, `enrolled`,
`configured_clients`. `settings-preview` возвращает перечисленные выше
сведения без ключей и идентификаторов клиентов. При отказе код завершения `2` — ожидаемая ошибка
проверки, `3` — неожиданная ошибка. Текст ошибки не содержит конфиг, Docker
stderr или ключи. Параметры `add` входят в argv процесса: передаётся только
**публичный** ключ.

Встроенный Python API — `AmneziaAdmin(TARGETS["awg2"]).enroll_preview()`,
`.enroll(id, confirm_image_id=..., confirm_config_sha256=...,
confirm_table_sha256=...)` или
`AmneziaAdmin(TARGETS["wireguard"]).enroll(id)`,
`.add(name, public_key, address)`,
`.create_profile(name, address, endpoint_host, recipient_public_key, route="split")`,
`.sealed_export(name, recipient_public_key)`, `.revoke(name)`, `.status()`,
`.settings_preview()` и `.recover()`.
Это root-only интерфейс с теми же проверками и JSON-совместимыми ответами.
Его **нельзя** вызывать непосредственно из веб-процесса или давать ему доступ
к Docker socket.

## Формат клиентского профиля

Для AWG3 `create-profile` берёт только разрешённые параметры из `[Interface]`
сервера: `Jc/Jmin/Jmax`, `S1–S4`, `H1–H4`, опциональные `I1–I5`,
`HeaderProtectionKey`, padding, rekey и флаги. `PrivateKey` сервера,
`PostUp`/`PostDown` и другие shell hooks никогда не копируются в профиль.
Серверный public key вычисляется из закрытого ключа и сверяется с runtime.
В клиентском `.conf` есть адрес `/32`, его закрытый ключ, `MTU = 1280`,
разрешённые AWG3 поля, PSK, адрес сервера и `PersistentKeepalive = 25`.
`add` по внешнему public key по-прежнему **не** создаёт профиль: закрытый
ключ находится вне SovaGrid, и `sealed-export` для такого клиента откажет.
Для стандартного WireGuard профиль содержит только адрес `/32`, закрытый
клиентский ключ, `MTU = 1280`, публичный серверный ключ, общий PSK, маршрут,
endpoint и keepalive. AWG поля и серверные shell hooks не копируются.

На одноразовом тестовом AWG3-сервере генерация профиля в памяти, расшифровка, handshake и ping прошли без сохранения или вывода ключей. Исходный код актуальной ветки
AmneziaVPN распознаёт `.conf` по `[Interface]`/`[Peer]` и переносит все поля
`awgProtocolKeys()`, включая `HeaderProtectionKey`, в AWG-конфигурацию.
Импорт именно в **установленное** приложение на iPhone/Android ещё не
выполнялся. Полноценный `vpn://` bundle также пока не генерируется.

## Транзакция и восстановление

Состояние: `/var/lib/sovagrid-vpn/amnezia-admin/`, каталоги `0700`, файлы
`0600`; owner root. Перед каждым изменением проверяются pinned identity,
хеши конфига и реестра, общий PSK, все существующие peer и runtime. Если
AmneziaVPN или оператор изменили файлы после `enroll`, запись отказывается.
Дополнительный peer добавляется одной секцией `[Peer]`, существующие секции
сохраняются побайтно. Отзыв удаляет только секцию принадлежащего SovaGrid
ключа и его строку реестра. Режим серверных файлов сохраняется.

До записи журнал `TARGET.pending` хранит точные исходные файлы и состояние.
Каждый файл внутри контейнера заменяется через временный файл и `mv`;
`awg/wg syncconf` применяет разницу к runtime без остановки интерфейса.
После этого сверяются все прежние peer, интерфейс, реестр и ожидаемые хеши.
При ошибке код возвращает исходные файлы и runtime, проверяет результат и
оставляет отказ, даже если откат удался. Если автоматический откат не прошёл,
дальнейшие изменения заблокированы до восстановления:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m sovagrid_vpn.amnezia_admin recover awg2
```

`recover` сверяет container/image ID и исходные файлы журнала. Текущие
конфиг, реестр и набор runtime peer должны совпадать с исходным либо
намеренным состоянием; чужая правка блокирует откат, чтобы её не затереть.
Если после успешного изменения не удалось удалить журнал,
`cleanup_required=true`; `recover` подтверждает уже зафиксированное
состояние и удаляет журнал. Нельзя вручную удалять журнал для обхода
проверки: при сомнении сохраните закрытую копию и разберите состояние.

**Две независимые программы не могут атомарно поменять конфиг и
`clientsTable` одним `rename`.** Журнал обеспечивает восстановление при
прерывании и проверенных сбоях, но AmneziaVPN не использует блокировку
SovaGrid. Поэтому для записи в существующий сервер требуется окно без
параллельного управления AmneziaVPN. Если контейнер пересоздан, ID изменится,
автоматическое восстановление откажет; резервная копия журнала должна быть
разобрана вручную до принятия нового контейнера.

## Отдельный Unix-broker для панели

`sovagrid_vpn.amnezia_control` обслуживает только `/run/sovagrid-vpn/amnezia-control.sock`.
Root-процесс повторно проверяет UID подключившегося клиента (`root` или
системный `sovagrid`), точный JSON `{"argv":[...]}` и список команд. Agent/Hub
не получают Docker socket, root-права, путь к файлу, shell или произвольную
Docker-команду. На сокете доступны только:

```text
add-profile awg2 CLIENT ADDRESS ENDPOINT_HOST RECIPIENT_P256_PUBLIC_B64URL [--route split|full]
sealed-export awg2 CLIENT RECIPIENT_P256_PUBLIC_B64URL
revoke awg2 CLIENT
status awg2
settings-preview awg2
settings-plan awg2 OLD_CONFIG_SHA256 GENERATION '{"Jc":"5"}'
settings-intent awg2 OLD_CONFIG_SHA256 GENERATION PROPOSED_CONFIG_SHA256 '{"Jc":"5"}'
settings-apply awg2 OLD_CONFIG_SHA256 GENERATION PROPOSED_CONFIG_SHA256 '{"Jc":"5"}' CONFIRMATION_ID
# Первые пять форм также доступны с target=wireguard и format=wg-conf.
```

`add-profile` вызывает `create_profile` и возвращает JSON с `target`, `action`,
`client`, `configured_clients`, `cleanup_required`, `profile_format=awg3-conf|wg-conf`
и `sealed_profile`. Последнее поле — **ровно** конверт
`{version:1,ephemeral_public_key,salt,nonce,ciphertext}`. `sealed-export`
возвращает только такой конверт. Broker проверяет канонический base64url и
размеры P-256 точки 65 байт, salt 16, nonce 12, ciphertext не более 4096 байт.
В `add-profile` `ADDRESS` может быть точным литералом `auto`; ручной `add`
для внешнего ключа по-прежнему требует явный IPv4.
В `revoke`, `status` и `settings-preview` передаются только перечисленные в
коде поля. Preview ограничен 4096 байтами и не содержит ключей или списка
клиентов; Hub допускает его только для администратора выбранного Agent.
Ответ сокета: одна строка JSON `{"ok":true,"result":...}` или
`{"ok":false,"error":"..."}`. Никакой plaintext профиля через него не идёт.

`settings-intent` повторяет точный план, проверяет ноль клиентов, прежние
container/image, SHA-256, поколение, конфигурацию и runtime, затем выдаёт
случайный `confirmation_id` на 5 минут. Root хранит только его SHA-256 в
файле `0600`; второй активный intent блокируется. `settings-apply` принимает
ровно те же старый/предполагаемый SHA-256, поколение и JSON-патч. Он под той
же root-блокировкой проверяет все условия и **до записи** атомарно удаляет
подтверждение. Повторное применение и применение после истечения срока
отказываются. Этот handle может сохраняться в задании Hub SQLite до
исполнения, поэтому он не считается секретным ключом; его действие ограничено
одной заранее закреплённой заменой на сервере без клиентов. У Agent/Hub
дополнительно должны работать RBAC и пользовательское подтверждение команды.
Обе команды требуют **два** независимых root-owned маркера: обычный
`amnezia-control.enabled` и дополнительный
`/etc/sovagrid-vpn/amnezia-awg-settings.enabled`. Второй не создаётся при
обычном `arm` и остаётся выключенным после обновления старой установки.

`enroll`, `recover`, `add` с внешним ключом и операции Xray **не входят** в
протокол. Перед любой записью администратор локально сверяет полный Docker
container ID и выполняет `enroll TARGET --confirm-container-id HEX64`;
broker не может принять контейнер по запросу панели. В Hub требуется
проверка роли, повторное подтверждение выдачи/отзыва и аудит без ключей до
вызова Agent. Сам Unix UID не является ролью пользователя.

Шаблоны `deploy/sovagrid-amnezia-*` и установщик
`deploy/install-amnezia-control.py` являются **отдельным opt-in пакетом**.
Обычный `run.sh` их не устанавливает и не включает. Установщик требует Linux,
root, исходники в root-owned `/opt/sovagrid-src/sovagrid-vpn` и совпадающий
развёрнутый Python-пакет `/opt/sovagrid-vpn`; при изменении исходников сначала
повторно выполните обычный `run.sh`. Проверяются владельцы/права каталогов,
содержимое пакета и принадлежность ранее установленных unit/launcher файлов.
Чужие файлы не перезаписываются.

Все команды ниже запускаются **на отдельном тестовом сервере с одноразовым
контейнером**, пока не проверены версия мобильного клиента, роль и повторное
подтверждение в Agent/Hub и окно обслуживания для живого VPN:

```sh
cd /opt/sovagrid-src/sovagrid-vpn
sudo /usr/bin/python3 -I deploy/install-amnezia-control.py preview
sudo /usr/bin/python3 -I deploy/install-amnezia-control.py install
sudo /usr/bin/python3 -I deploy/install-amnezia-control.py preview
```

`preview --target awg2|wireguard` даёт JSON без ключей и записей: состояние
root-only маркера выбранной цели, socket/service, совпадение кода и read-only проверку закреплённого
контейнера, конфига, реестра и runtime. Docker вызывается только через
`inspect`, `exec stat`, `exec head` и `exec awg show ... dump`; результат
с ключами не печатается. `install` атомарно ставит launcher и systemd units,
проверяет их через `systemd-analyze verify` и делает `daemon-reload`, но **не** создаёт маркер, не включает и не запускает
socket/service. У service отсутствует секция `[Install]`, поэтому обычный
`systemctl enable sovagrid-amnezia-control.service` недоступен.

До `enroll awg2` поле `target.reason` в `preview` равно `AWG2 is not enrolled`;
это ожидаемое состояние, а не ошибка контейнера. Проверка содержимого
контейнера проводится только после закрепления его идентичности. `preview`
не создаёт файлы состояния или Python bytecode.

Для отдельного ручного включения сначала выполните root-only `enroll awg2`
после независимой сверки **полного** Docker ID, как описано выше. `arm`
повторно проверяет ID, image ID, текущее состояние и отсутствие незаконченной
операции. Он принимает только фиксированную строку подтверждения окна и
включает **только** socket:

```sh
docker container inspect --format '{{.Id}}' amnezia-awg2
sudo /usr/bin/python3 -I deploy/install-amnezia-control.py arm \
  --confirm-container-id FULL_64_HEX_CONTAINER_ID \
  --confirm-maintenance-window I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2
sudo /usr/bin/python3 -I deploy/install-amnezia-control.py disarm
```

`arm` атомарно создаёт маркер выбранной цели: для AWG2 —
`/etc/sovagrid-vpn/amnezia-control.enabled`, для WireGuard —
`/etc/sovagrid-vpn/amnezia-wireguard-control.enabled`. Оба root:root `0600`
с точным содержимым `enabled\n`. Broker проверяет нужный маркер **при каждом
запросе**; один маркер не разрешает операции над другой целью. Установщик
сериализует `install`/`arm`/`disarm` root-owned блокировкой, чтобы общий
socket не выключился при одновременном включении второй цели. Для WireGuard
нужны `arm --target wireguard` и подтверждение
`I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_WIREGUARD`. При ошибке включения
socket установщик удаляет новый маркер. `disarm --target awg2|wireguard`
удаляет только маркер выбранной цели; общий socket выключается после
отключения обеих. Это не прерывает уже исполняющуюся операцию: после проверки
её завершения и recovery state root может остановить service вручную.
Перед обновлением исходников или повторным `install` сначала выполните
`disarm` и проверьте отсутствие работающего broker. Само по себе включение
socket не добавляет peer и не меняет контейнер; к записи приводит только
явный разрешённый запрос после отдельного принятия контейнера под управление.
Текущие live Amnezia контейнеры остаются read-only.

Для отдельного включения **только** AWG3 numeric settings на сервере без
клиентов графический мастер может вызвать `preview-settings`, затем после
подтверждения полного container ID и окна обслуживания — `arm-settings`.
`preview-settings` возвращает `settings_marker`, `peer_marker`,
`socket_active`, `target_ready`, `container_id`, `configured_clients`,
`awg3_runtime_verified`, `can_arm`, `reason` и не меняет конфиг контейнера.
`reason` равен `null` при готовности либо одному коду:
`INSTALL_NOT_CURRENT`, `TARGET_UNAVAILABLE`, `CLIENTS_PRESENT`,
`AWG3_INCOMPLETE`, `RUNTIME_UNVERIFIED`, `POLICY_NOT_READY`, `POLICY_UNSAFE`,
`ALREADY_ARMED`. Если `target_ready=false`, `container_id` и
`configured_clients` равны `null`; маркеры отражаются независимо, чтобы
показать повреждённое состояние без предположений о его причине.
`arm-settings` повторяет read-only проверку селекторов и отсутствие клиентов
перед созданием второго маркера. `disarm-settings` выключает только настройки;
обычный `disarm --target awg2` выключает оба маркера. Ни одна из этих команд
не меняет AWG3-параметры сама.

```sh
sudo /usr/bin/python3 -I deploy/install-amnezia-control.py preview-settings
sudo /usr/bin/python3 -I deploy/install-amnezia-control.py arm-settings \
  --confirm-container-id FULL_64_HEX_CONTAINER_ID \
  --confirm-maintenance-window I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG3_SETTINGS
sudo /usr/bin/python3 -I deploy/install-amnezia-control.py disarm-settings
```

## Проверка и ввод в панель

Автоматические тесты: `python3 -m unittest discover -s tests -q`. Отдельный
скрипт `lab/amnezia_admin_docker.py` запускает контейнеры с префиксом
`sg-amnezia-fixture-` без сети, открытых портов и bind mounts и проверяет
`enroll → add → revoke` и ошибку `syncconf → rollback` для AWG2 и WireGuard.
Отдельный `lab/amnezia_profile_docker.py` создаёт внутреннюю Docker-сеть и
два одноразовых AWG3 контейнера: новый peer получает sealed `.conf`, клиент
его расшифровывает, применяет и проверяет handshake/ping; отзыв удаляет peer.
Контейнеры и сеть удаляются после теста. Синтетический AWG3 `.conf` успешно
импортирован в официальный AmneziaVPN 5.0.1.5 на Android-эмуляторе; проверка
handshake на физическом телефоне и запись на живых контейнерах не выполнялись.

Перед первым изменением живого AWG2 нужны проверка шаблонов broker на staging,
роль и подтверждение в Hub, аудит без секретов, повторный стендовый прогон
после обновления образа и окно обслуживания. Xray VLESS пока не входит в CLI: на текущем
сервере не включён `HandlerService`, а изменение `server.json` требует
рестарта контейнера и разрыва действующих соединений.

Основание формата peer и `syncconf` —
[исходный код AmneziaVPN](https://github.com/amnezia-vpn/amnezia-client/blob/dev/client/core/configurators/wireguardConfigurator.cpp),
а структура строк `clientsTable` и логика отзыва —
[UsersController](https://github.com/amnezia-vpn/amnezia-client/blob/dev/client/core/controllers/selfhosted/usersController.cpp).
Набор полей `.conf` взят из [официального AWG template](https://github.com/amnezia-vpn/amnezia-client/blob/dev/client/server_scripts/awg/template.conf),
а проверка пути импорта — из [ImportController](https://github.com/amnezia-vpn/amnezia-client/blob/dev/client/core/controllers/selfhosted/importController.cpp)
и [списка `awgProtocolKeys`](https://github.com/amnezia-vpn/amnezia-client/blob/dev/client/core/utils/constants/configKeys.h).
