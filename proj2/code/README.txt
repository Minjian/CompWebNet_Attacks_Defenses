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
References:
* https://stackoverflow.com/questions/3240246/signed-session-cookies-a-good-idea

In the Attack Charles, we replace the current cookie with a target cookie so that
we can convince the server we are another user. We can defense this by signing the
session based a server secret key together with user name and password. Then we check the
session if it has the correct signature. If the session doesn't have the correct signature,
we force to logout the session and ask users to login again.


## 4.4 Defense Delta: Cooking the Books with Cookies
References:
* https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/stringify

When doing this defense, Defense Charlie cannot cover Attack Delta. The reason for that
is because we only sign the session based on the username and password. Attack Delta would
change the "bitbars" value. Hence, we change to sign the session by using the content of the
session.account. To do that, we take advantage of the "JSON.stringify()" function.

However, as now we sign the session by using the content of the session.account, we need to
update the session signature once users update their account content (e.g. bitbars, profile).

In addition, we also need to carefully check the return value of the "JSON.stringify()" function,
which can be a JSON string representing the given value, or undefined.


## 4.5 Defense Echo: SQL Injection
References:
* https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/test
* https://stackoverflow.com/questions/64830748/regex-for-validating-username

In Defense Echo, we change all SQL query to use parameterized SQL mentioned in the
web attack lecture as well as checking if the username input complies our username pattern.

For the username regex, we take advantage of an existing example from StackOverflow. But we can
change that to meet other specific requirements.

## 4.6 Defense Foxtrot: Profile Worm
References:
* https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
* https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/some

If users are only allowed to set their profile in text without any HTML tag, we can simply
sanitize the profile input like what we did in Defense Alpha. However, based on the project
requirement, we cannot over-sanitize inputs so we didn't sanitize profile in the
"sanitized_object" function.

With such a condition, we can check if the profile has dangerous content that could cause
XSS attacks. Based on "Content Security Policy Cheat Sheet", we use "xss_restricted_content"
to include common tags used by XSS attacks. If the user profile contains any tag, we notify
the user to revise the profile.

As we are not allowed to modify the "views/pages/index.ejs" file, the message is implemented
as req.session.account.profile to show users about what tags need to be avoided.

## 4.7 Defense Gamma: Password Extraction via Timing Attack
