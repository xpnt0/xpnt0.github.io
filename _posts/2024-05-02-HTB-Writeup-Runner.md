---
title: "HTB Writeup: Runner"
author: xpnt
date: 2024-05-02
image:
  path: https://pbs.twimg.com/media/GLcUA3FXwAAZSWE?format=jpg&name=medium
  height: 1500
  width: 500
categories: [Hack The Box]
tags: [labs,docker,teamcity]
---

[Link: Pwned Date](https://www.hackthebox.com/achievement/machine/1504363/598)


- Comenzamos con un escaneo de puertos, con ello descubrimos que los puertos `22,80,8000` están abiertos. Notando que existe un dominio `runner.htb`, el cual procedemos a añadir al archivo `/etc/hosts`
![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427003051.png)

- Dado que el servicio HTTP por el puerto `8000` no presenta nada interesante, procedemos a analizar el puerto `80`
![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427003342.png)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427003512.png)

- Al inspeccionar el puerto `80` nos permite entender que `runner.htb` brinda servicios de  *CI/CD*, sin embargo no existe ningún recurso ni directorio interesante.
![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427005859.png)

- En el puerto `80` dada la existencia de un dominio `runner.htb`, procedemos a realizar un fuzzing de virtual hosts usando *gobuster* con la sisguiente [wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/bitquark-subdomains-top100000.txt). Se encontró el vhost `teamcity.runner.htb` el cual procederemos a añadir al `/etc/hosts`

!(/assets/images/HTB-Writeup-Runner/Pasted image 20240427010542.png)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427004040.png)

- Una vez accedemos al vhost `teamcity.runner.htb`, nos encontramos con un portal de inicio de sesión del software *TeamCity*. Podemos observar que se trata de la versión `2023.05.3`, es por ello que realizaremos una búsqueda de vulnerabilidades.
![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427021210.png)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427021249.png)

- Encontramos el *CVE-2023-42793* el cual permite la creación de un *usuario administrador* y lograr **RCE**. Una explicación más a detalle en este [blog](https://blog.projectdiscovery.io/cve-2023-42793-vulnerability-in-jetbrains-teamcity/). Usaremos el siguiente [PoC](https://github.com/Zenmovie/CVE-2023-42793)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427021609.png)

- Con uno de los PoC podemos crear una cuenta con privilegios de administrador con el *admin token*. Otorgándonos las siguientes credenciales `Zenmovie:Zenmovie`

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427025446.png)

- Cabe mencionar que para que podamos lograr la creación de un usario administrador y lo más importante, lograr RCE,  es necesario conocer el *userId*  de un usuario con privilegios de administrador para que pueda habilitar la propiedad `rest.debug.processes.enable` en `true` . Normalmente el `userId=1` le corresponde al usuario `admin`. Dicha afirmación se puede corroborar al acceder al panel de Administración e ingresar al perfil del usuario.

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427024413.png)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427030047.png)

- Luego podremos lograr RCE.
![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427030142.png)

- Cabe indicar que también podemos lograr RCE con el nuevo usuario creado (`Zenmovie`), pues posee privilegios de administrador, bastaría con modificar el *useId* en el código Bash del PoC.
![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427030728.png)
![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427133557.png)

- El PoC no funciona correctamente si queremos obtener una *reverse shell*, después de analizar el código Bash, notamos la ausencia del query GET parameter `params` , el cual permite agregar *parámetros* a los comandos a ejecutar. Es por ello que modificaremos el script Bash del PoC y adjuntaremos dicho query parameter.

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427031237.png)

 - Una solución más sencilla hubiera sido interceptar la solicitud con el proxy BurpSuite y modificarlo manualmente para poder ejecutar comandos con parámetros. Para lograr ello bastaría con añadir `--proxy http://127.0.0.1:8080` al comando *cURL* y posteriormente habilitar el *Proxy->Intercept
 ![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427031758.png)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240427031703.png)

 - De cualquier forma, no logramos obtener reverse shell debido a que se trata de un docker.
![](/assets/images/HTB-Writeup-Runner/Pasted image 20240501063423.png)

 - Revisando la funcionalidades presentes en la web, como administrador, notamos la existencia de la funcionalidad `Backup` es por ello que realizaremos la creación de un archivo backup. [Source](https://www.jetbrains.com/help/teamcity/2023.05/creating-backup-from-teamcity-web-ui.html)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240501065551.png)


- Al analizar el contenido del ZIP file. Nos llama la atención el `database_dump/users` el cual parece contener los hash de las credenciales para los usuarios dentro del TeamCity. 
![](/assets/images/HTB-Writeup-Runner/Pasted image 20240501070144.png)

- Usando `hashcat` para crackearlos. Descubrimos que las credenciales para el user `john`(Adminsitrador) es `piper123`.
![](/assets/images/HTB-Writeup-Runner/Pasted image 20240501071213.png)

- Suponiendo que se hizo una reutilización de credenciales. Intentamos loguearmos como `matthew` y como `john` , pero no tenemos éxito. Adicionalmente revisando más a fondo las funcionalidades de la web, notamos que podemos crear `id_rsa` para modificar el proyecto a través de una consola.

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240501072708.png)

- Es por ello que dentro del ZIP file encontramos un `id_rsa`, el cual nos permite generar una *public key*  el cual nos permite descubrir que dicha `id_rsa` le pertenece al usuario `john`. Con ello podemos loguearnos por SSH.

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240501073241.png)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240501073358.png)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240501073649.png)

- Encontramos que existe un servicio `HTTP` corriendo internamente en el puerto `9000`. Realizaremos un `SSH Local Port Forwarding` para poder revisar dicho servicio más a detalle.

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240501075606.png)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240501080013.png)

- Analizando dicho servicio, notamos que se trata de `portainer.io`. En el cual podemos ingresar con las credenciales `matthew:piper123` y visualizamos su version (`2.19.4`)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240501080240.png)

- Para lograr acceder como root en el target. Es bueno entender los conceptos de Portainer.io, `Volumes Tab vs Volumes Bind`. Para mayor información en [Source](https://www.reddit.com/r/portainer/comments/1apyvya/portainer_volumes_tab_vs_container_volumes_bind/). Luego procederemos a crear un volume con las siguentes driver options. Para mayor información en [Source](https://help.nextcloud.com/t/external-hhd-is-not-recognized-by-nextcloud/159878/9)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240502102557.png)

- Luego procederemos a crear un container `ContainerPwned`con una imagen que está a nuestra disposición (`teamcity:latest`).
![](/assets/images/HTB-Writeup-Runner/Pasted image 20240502102737.png)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240502102809.png)

- Luego podemos acceder a una consola dentro del container y lograr acceder al directorio /root del target mediante el mount point.

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240502103345.png)

![](/assets/images/HTB-Writeup-Runner/Pasted image 20240502103440.png)