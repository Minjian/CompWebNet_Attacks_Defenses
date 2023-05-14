## 4.1 Defense Alpha: Cookie Theft
References:
* https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
* https://stackoverflow.com/questions/2794137/sanitizing-user-input-before-adding-it-to-the-dom-in-javascript

For defensing attack alpha, we need to prevent malicious user input being rendered in our website.
Hence, we need to sanitize our "render" function as much as possible including the title,
account content, error message and result.

Thanks to the references, we know there are many sanitizer out there. DOMPurify is recommended by many sites.
Unfortunately, our web app doesn't support DOMPurify at this moment unless we upgrade our web framework.
So we take advantage of a sample "sanitize" function from StackOverflow to help us do input sanitization.


## 4.2 Defense Bravo: Cross-Site Request Forgery
References:
* https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
* https://www.w3schools.com/jsref/met_win_setinterval.asp

For defensing attack bravo, we can HMAC a token with a secret key known only by the server and add
the token to the form. Every time when we receive a form, we would validate the token value.

By default, we will change the secret key very 5 minutes. We can change the timeout value based on
the requirement.


## 4.3 Defense Charlie: Session Hijacking with Cookies


## 4.4 Defense Delta: Cooking the Books with Cookies


## 4.5 Defense Echo: SQL Injection


## 4.6 Defense Foxtrot: Profile Worm


## 4.7 Defense Gamma: Password Extraction via Timing Attack
