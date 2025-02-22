# phpMyFAQ: CVE-2024–54141 - Triggering the Exposure of DB Creds
Exposure of database (ie postgreSQL) server’s credential when connection to DB fails.

## Details
Exposed database credentials upon misconfig/DoS: https://github.com/thorsten/phpMyFAQ/blob/main/phpmyfaq/src/phpMyFAQ/Setup/Installer.php#L694

## POC
When postgreSQL server is unreachable, an error would be thrown exposing the credentials of the database. For instance, when “http://:8080/setup/index.php" is hit when the database instance/server is down, then credentials are exposed, for instance:
```
( ! ) Warning: pg_connect(): Unable to connect to PostgreSQL server: connection to server at &quot;127.0.0.1&quot;, port 5432 failed: Connection refused Is the server running on that host and accepting TCP/IP connections? in /var/www/html/src/phpMyFAQ/Database/Pgsql.php on line 78
Call Stack
# Time Memory Function Location
1 0.0404 453880 {main}( ) .../index.php:0
2 1.1341 610016 phpMyFAQ\Setup\Installer->startInstall( $setup = ??? ) .../index.php:471
3 1.2113 611544 phpMyFAQ\Database\Pgsql->connect( $host = '127.0.0.1', $user = 'cvecve', $password = '<redacted>', $database = 'cvecve', $port = 5432 ) .../Installer.php:694
4 1.2113 611864 pg_connect( $connection_string = 'host=127.0.0.1 port=5432 dbname=cvecve user=cvecve password=<redacted>' ) .../Pgsql.php:78

( ! ) Fatal error: Uncaught TypeError: Cannot assign false to property phpMyFAQ\Database\Pgsql::$conn of type ?PgSql\Connection in /var/www/html/src/phpMyFAQ/Database/Pgsql.php on line 78
( ! ) TypeError: Cannot assign false to property phpMyFAQ\Database\Pgsql::$conn of type ?PgSql\Connection in /var/www/html/src/phpMyFAQ/Database/Pgsql.php on line 78
Call Stack
# Time Memory Function Location
1 0.0404 453880 {main}( ) .../index.php:0
2 1.1341 610016 phpMyFAQ\Setup\Installer->startInstall( $setup = ??? ) .../index.php:471
3 1.2113 611544 phpMyFAQ\Database\Pgsql->connect( $host = '127.0.0.1', $user = 'cvecve', $password = '<redacted>', $database = 'cvecve', $port = 5432 ) .../Installer.php:694
```

![image](https://github.com/user-attachments/assets/4035624f-24e9-4609-a684-0c12c1953078)

A way to force this would be to perform a denial of service on the database instance/server. When the db connection is refused, the credentials would show. The remote attacker can then use that to gain full control on the database.

## Impact
This vulnerability exposes the credentials of the database and grants a remote attacker full control over the database.

## Reference
https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-vrjr-p3xp-xx2x

# phpMyFAQ: CVE-2024–55889 - phpMyFAQ Triggering Unintended File Downloads

Unintended File Download Triggered by Embedded Frames

## Summary
A vulnerability exists in the FAQ Record component of https://github.com/thorsten/phpMyFAQ v3.2.10 where a privileged attacker can trigger a file download on a victim’s machine upon page visit by embedding it in an <iframe> element without user interaction or explicit consent.

## Details
In http://localhost/admin/index.php?action=editentry&id=20&lang=en, where a FAQ record is either created or edited, an attacker can insert an iframe, as “source code”, pointing to a prior “malicious” attachment that the attacker has uploaded via FAQ “new attachment” upload, such that any page visits to this FAQ will trigger an automated download (from the edit screen, download is automated; from the faq page view as a normal user, depending on the browser, a pop up confirmation may be presented before the actual download. Firebox browser, for instance, does not require any interactions).

![image](https://github.com/user-attachments/assets/8cdb4eca-4396-4c16-a901-c63dfc565cab)

## POC
1. create a new FAQ record and upload a “malicious” file — in my case, I uploaded an eicar file. Take note of the uri, ie “index.php?action=attachment&id=2”
2. in the FAQ record, insert a “source code” blob using the “< >” button
3. insert in the following snippet and save FAQ record:
```
<p><iframe src="index.php?action=attachment&id=2"></iframe></p>
```
![image](https://github.com/user-attachments/assets/8a5ab341-af66-42e1-9768-3201356746e8)

Once the edit page reloads, the malicious code will be downloaded onto the local machine without user interaction:

![image](https://github.com/user-attachments/assets/6be31e91-8cbe-46b5-b390-317e637cff25)

## Weakness
CWE-451

## CVSS v3
4.9

## Impact 
Malicious code or binaries could be dropped on visitors’ machines when visiting the FAQ platform. Take a worm or ransomware for instance.

## Reference
https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-m3r7-8gw7-qwvc


# phpMyFAQ: CVE-2024–56199 - Stored HTML Injection
## Summary
Due to insufficient validation on the content of new FAQ posts for the phpmyfaq project, it is possible for authenticated users to inject malicious HTML or JavaScript code that can impact other users viewing the FAQ. This vulnerability arises when user-provided inputs in FAQ entries are not sanitized or escaped before being rendered on the page.

## Details
An attacker can inject malicious HTML content into the FAQ editor at http://localhost/admin/index.php?action=editentry, resulting in a complete disruption of the FAQ page’s user interface. By injecting malformed HTML elements styled to cover the entire screen, an attacker can render the page unusable. This injection manipulates the page structure by introducing overlapping buttons, images, and iframes, breaking the intended layout and functionality.

**CVSS v3**: 5.2 / 10
**CWE-80**: Improper Neutralization of Script-Related HTML Tags in a Web Page

## POC
1. In the source code of a FAQ Q&A post, insert the likes of this snippet:
```
<p>&lt;--`<img src="&#96;"> --!&gt;</p>
<div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;"><form><button>HTML INJECTION 1<img> <img> <img> <img> <iframe></iframe></button>
<div style="xg-p: absolute; top: 0; left: 0; width: 100%; height: 100%;">x</div>
<button>HTML INJECTION 2<iframe></iframe> <iframe></iframe> </button></form></div>
```
![image](https://github.com/user-attachments/assets/42fcd335-c55b-4a74-8361-382dd76c2336)

2. A normal user would see the broken FAQ page, or otherwise manipulated by the attacker to present a different malicious page:
![image](https://github.com/user-attachments/assets/d666bc66-a8cc-4fa5-8aa7-aa380e03745d)

## Impact
Exploiting this issue can lead to Denial of Service for legitimate users, damage to the user experience, and potential abuse in phishing or defacement attacks.

## Reference
https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-ww33-jppq-qfrp
