# Att göra: Claude in Brave

Senast uppdaterad: 2026-10-20. Byggt och testat finns beskrivet i README.

## Finns och är testat live
- [x] Skriva i textfält, kryssa i kryssrutor, klicka på knappar och länkar
- [x] Välja i egna menyer och förslag (`pick`)
- [x] Datum i kalender med månadsbyte (`date`)
- [x] Rulla till element, hovra, vänta på element
- [x] Läsa hela formuläret i ett anrop (`/form`), och köra många steg i en batch (`/batch`)

## Finns men inte testat live
- [ ] Dra och svepa (`drag`), mot en riktig sajt
- [ ] Välja i vanlig lista (`choose`)
- [ ] Datumfält av typen `<input type="date">` (kod finns, inget testfält)

## Saknas
- [ ] Piltangenter och mellanslag i `press` (menyer kräver dem)
- [ ] Iframes och flera flikar i en batch
- [ ] Touch-svep för telefon (bara musdrag finns)
- [ ] Värden i valda brickor (ämnen m.m.) i `/form`
- [ ] Stabila fältnamn på dynamiska sidor (t.ex. Google Forms efter att frågor lagts till)

## Regressioner och kända brister
- [ ] `/network` visar inte längre svarskroppar (avsiktligt, för att avlasta pipen). Lägg tillbaka vid behov, på begäran.
- [ ] GPU-fel i Braves logg (`brave.log`). Brave kan behöva startas om ibland.
- [ ] Tester är enhetstester mot falsk sida. JavaScript är bara syntaxkontrollerat, inte körts i en testmiljö.

## Medvetet inte byggt
- Filuppladdning blockeras med avsikt.
