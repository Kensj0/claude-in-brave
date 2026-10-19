# claude-in-brave

Claude styr Brave: läsa sidor som text, agera på dem, och sköta åtkomst och godkännanden. Körs från en terminal, utan Jarri.

## Kom igång

1. Starta tjänsten i en terminal:

   ```
   python3 server.py
   ```

   Den startar Brave i ett eget fönster när ett verktyg behöver det. Standardport är 8786.

2. Koppla Claude Code till den, en gång:

   ```
   claude mcp add claude-in-brave -- python3 /SÖKVÄGEN/TILL/mcp.py
   ```

   Byt `/SÖKVÄGEN/TILL/mcp.py` mot den riktiga sökvägen till filen.

Claude kan då läsa sidor, öppna sidor den får använda och agera på dem. Den kan inte själv ge sig åtkomst till en sajt eller godkänna en riskfull åtgärd. Det gör du, i terminalen eller i en panel.

## Det du gör själv

- **Ge åtkomst till en sajt:** `POST /permissions {"origin": "https://exempel.se", "hours": 2}`. Utan åtkomst får Claude inte öppna sajten.
- **Godkänna en riskfull åtgärd** (skicka, betala, ta bort): `POST /approvals {"id": ..., "approve": true}`.
- **Stoppa allt:** `POST /pause {"on": true}`.
- **Se vad som hänt:** `GET /events`.

Lösenord läses aldrig, och Claude skriver aldrig i lösenordsfält. Logga in i Brave-fönstret själv.

## Inställningar

Miljövariabler, alla valfria:

| Variabel | Standard | Vad |
|---|---|---|
| `JARRI_BROWSER_PORT` | 8786 | port för tjänsten |
| `JARRI_BRAVE_BIN` | /opt/brave.com/brave/brave | sökväg till Brave |
| `JARRI_BROWSER_PROFILE` | ~/.brave-claude | Braves profil för Claude, skild från din vanliga |
| `JARRI_BROWSER_HEADLESS` | 0 | 1 = Brave utan fönster |

## Licens

Copyright (c) 2026 Kenny Sjöstedt.

Licensierad under GNU Affero General Public License v3.0 (se [LICENSE](LICENSE)).

Kommersiell licens finns hos upphovsmannen för användning som AGPL inte tillåter. Kontakta upphovsmannen via GitHub.
