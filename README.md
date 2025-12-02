# ESP-IDF WiFi Analyzer (ESP32-C6)
Demonstracijski projekt, ki prikazuje uporabo **ESP-IDF** kot izbrane tehnologije za razvoj firmware-a na ESP32-C6 z naprednim Wi-Fi promiscuous načinom delovanja. Projekt zajema zajem 802.11 paketov, dekodiranje Beacon okvirov ter detekcijo WPA2/WPA3 EAPOL 4-way handshake-a.

---

## 🎯 Zakaj ESP-IDF?
ESP-IDF je uradni *industrial-grade* razvojni framework podjetja Espressif za vse njihove ESP32 mikrokontrolerje.  
V primerjavi z Arduino okoljem ponuja:

- nizko-nivojski dostop do Wi-Fi driverjev,
- stabilno real-time okolje (FreeRTOS),
- visoko prilagodljiv build sistem (CMake, Kconfig),
- podporo za kompleksne Wi-Fi funkcije (promiscuous mode, sniffer, raw packets),
- podporo za industrijske IoT aplikacije.

ESP-IDF predstavlja tehnologijo, ki **ni bila obravnavana pri študiju** (ni standardni Arduino ali preprosti IoT pristopi), zato ustreza pogojem naloge.

---

## ✔ Prednosti
- Odprtokoden, industrijski standard.  
- Dostop do nizko-nivojskih funkcij (WiFi RAW paketov, promiscuous mode).  
- Stabilna Wi-Fi 6 podpora na ESP32-C6.  
- Odličen za varnostne in raziskovalne aplikacije.  
- Integriran FreeRTOS (večopravilnost).  
- Možnost OTA, TLS, HTTP, BLE, ...  
- Velika skupnost, aktivni razvijalci.

## ✖ Slabosti
- Zahteva dobro znanje C in embedded konceptov.  
- Težji build sistem (CMake).  
- Ni tako “plug and play” kot Arduino.  

---

## 📜 Licenca
ESP-IDF je sproščen pod licenco **Apache License 2.0**, ki dovoljuje prosto rabo, modifikacijo in komercialno uporabo.

---

## 👥 Število uporabnikov
- ESP-IDF ima več kot **8.000 GitHub forkov**, tisoče komercialnih uporabnikov.  
- Ena najbolj razširjenih IoT platform na svetu.

---

## ⚙ Vzdrževanje tehnologije
| Lastnost | Podatek |
|---------|---------|
| Število aktivnih razvijalcev | ~950 |
| Zadnja sprememba | 27.11.2025 |
| GitHub repo | [github.com/espressif/esp-idf](https://github.com/espressif/esp-idf) |
| Podpora | forum, GitHub Issues, Discord |

---

## ⏱ Časovna in prostorska zahtevnost
- **Compile time:** 5–20 sekund (odvisno od modula)  
- **Velikost firmware-a:** 600 kB – 1.5 MB  
- RAM poraba:
     - FreeRTOS kernel: ~10 kB
     - Wi-Fi driver: 70–150 kB
     - Sniffer callback stack: ~4 kB na task
- Flash poraba na ESP32-C6: ~1 MB od 4 MB


---

Ta projekt demonstrira osnovno uporabo ESP-IDF za delo z Wi-Fi paketnim snifferjem:

- zajem 802.11 Beacon, Probe, Data okvirjev  
- dekodiranje SSID-jev, enkripcije (WPA2/WPA3)  
- OUI vendor lookup (Apple, Samsung, TP-Link, …)  
- detekcija randomiziranih MAC naslovov  
- identifikacija WPA2/WPA3 handshake paketov (Message 1/4 – 4/4)  
- HEX izpis celotnega paketa  
- kanalni hopping ali kanalni lock  

### 📸 Screenshot (primer iz terminala)
<img width="611" height="477" alt="image" src="https://github.com/user-attachments/assets/63826a1d-2b91-4b49-912e-be656a142b96" />

