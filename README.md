# Názov: ipk-scan

## Aplikácia testuje stav zadaných portov na zadanej adrese. Stavy portov mozu byt open, closed a filtered pre TCP a open a closed pre UDP.

Obmedzenie:
Aplikácia nepodporuje prepínač -i pre výber sieťového rozhrania. prepínač síce akceptovaný bude, dokonca bude tento výber zobrazený vo výpise z aplikácie ale pre
chod aplikácie samotnej to nemá žiadny vplyv.

Preklad:
Aplikácia sa dá preložiť pomocou príkazu "make". Preložená aplikácia sa bude nachádzať v adresáry "build", ktorý bude v roote rozbaleného priečinka.

Príklad spustenia:
Linux: ./ipk-scan --pt 1,2,3 --pu 20-50 localhost	Skenované budú porty budú 1,2,3 pre TCP a rozsah 20 až 50 pre UDP na adrese localhost (127.0.0.1)

Zoznam súborov v adresári:
ipk-scan.csproj
Program.cs
makefile
README.txt
manual.pdf
