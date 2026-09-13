# Архітектура: шари й тестові групи

Джерело: граф імпортів `src/*.py`.

## Шари

- **L0 — конфіг**: `tuning.py`. Лише stdlib (`dataclasses`).
- **L1 — домен**: кожен модуль імпортує лише `tuning.py`, без L1→L1 імпортів.
  - `connection.py` — деривація ключа, хендшейк.
  - `exchange.py` — архіви (`pyzipper`).
  - `local_config.py` — профіль користувача.
  - `nat_traversal.py` + `stun_client.py` — NAT (UPnP/STUN), два окремих модулі одного шару.
  - `transport.py` — сокети, HMAC, AES-CTR.
- **L2 — ui**: `appearance.py` — імпортує всі L1-модулі й `tuning.py`.
- **L3 — точка входу**: `secure_file_drop_entry.py` — імпортує лише `appearance.py`.

```
tuning.py (L0)
  ^
  |-- connection.py ---\
  |-- exchange.py ------\
  |-- local_config.py ---+--> appearance.py (L2) --> secure_file_drop_entry.py (L3)
  |-- nat_traversal.py -/
  |-- stun_client.py --/
  |-- transport.py ----/
```

## Модуль → шар → тестова група

| Модуль | Шар | Тестова група |
|---|---|---|
| `tuning.py` | L0 | (нема власного файла тестів — див. "Зміна → групи") |
| `connection.py` | L1 | `handshake` (`test_connection.py`) |
| `exchange.py` | L1 | `data` (`test_exchange.py`) |
| `local_config.py` | L1 | `profile` (`test_local_config.py`) |
| `nat_traversal.py` | L1 | `nat` (`test_nat_traversal.py`) |
| `stun_client.py` | L1 | `nat` (`test_stun_client.py`) |
| `transport.py` | L1 | `transport` (`test_transport.py`) |
| `appearance.py` | L2 | `gui` (`test_appearance.py`) |
| `secure_file_drop_entry.py` | L3 | `cli` (`test_secure_file_drop_entry.py`) |

Аліаси груп: `fast` = handshake + data + profile + nat + cli; `all` = усі групи.

## Зміна → групи (що запускати)

`appearance.py` імпортує всі L1-модулі — зміна БУДЬ-ЯКОГО L1-модуля може зачепити GUI, завжди додавайте `gui`.

| Змінено | Запустити |
|---|---|
| `connection.py` | `handshake`, `gui` |
| `exchange.py` | `data`, `gui` |
| `local_config.py` | `profile`, `gui` |
| `nat_traversal.py` або `stun_client.py` | `nat`, `gui` |
| `transport.py` | `transport`, `gui` |
| `appearance.py` або assets, що вона вантажить | `gui` (+ `cli`, якщо змінено конструктор `SecureFileClientApp`) |
| `secure_file_drop_entry.py` | `cli` |
| `tuning.py`: `ConnectionTuning`/`CONNECTION` | `handshake`, `gui` |
| `tuning.py`: `NatTuning`/`StunTuning` (`NAT`/`STUN`) | `nat`, `gui` |
| `tuning.py`: `ProfileTuning`/`PROFILE` | `profile`, `gui` |
| `tuning.py`: `AppearanceTuning`/`APPEARANCE` | `gui` |
| `tuning.py`: `ExchangeTuning`/`EncryptionTuning` (`EXCHANGE`/`ENCRYPTION`) | `data`, `gui` |
| `tuning.py`: `TransportTuning`/`TRANSPORT` | `transport`, `gui` |
| `tuning.py`: структурна зміна (новий датаклас, перейменування, спільні поля) | `all` |
| `tests/_pathfix.py`, `tests/_groups.py`, `bin/run-tests`, `bin/run-tests.bat`, `requirements.txt` | `all` |
| Один `tests/test_X.py` | своя група (таблиця вище) |
| Тільки `docs/*.md` | нічого |

## Команди

```
python tests/_groups.py <група...>       # напр. python tests/_groups.py data gui
bin/run-tests <група...>                  # Linux/macOS, той самий скрипт
bin\run-tests.bat <група...>              # Windows
python tests/_groups.py --list            # список груп і аліасів
python tests/_groups.py handshake -v      # unittest-прапорці passthrough
python tests/_groups.py data -k prepare   # -k PATTERN теж passthrough
```

## Відомі проблеми

- Група `transport` повільна й іноді флейкає (див. `docs/testing.md`).
