## 3.1 Exploit Alpha: Cookie Theft
* HTML hidden: https://www.w3schools.com/tags/att_global_hidden.asp
* URL replace: https://www.w3schools.com/jsref/met_loc_replace.asp


## 3.2 Exploit Bravo: Cross-Site Request Forgery
By using the FireFox "inspect" feature, when we do a transfer from user1 to user2, we know the request header is
```
POST /post_transfer HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
......
```

and the request body is
```
destination_username=user2&quantity=20
```

Hence, we can create a XMLHttpRequest to set the request header to be a "application/x-www-form-urlencoded" form
and send out "destination_username=attacker&quantity=10" as the form data. Then, we can steal 10 Bitbars from
user account and deposit to the attacker account.

XMLHttpRequest: https://www.w3schools.com/js/js_ajax_http.asp


## 3.3 Exploit Charlie: Session Hijacking with Cookies
Based on the code in router.js, the app uses "session.account" to maintain user's session.
In the "/post_transfer" function, we know it would check "req.session.account.bitbars"
and "req.session.account.username" to validate the transfer.
Hence, in this attack, we need to overwrite those 2 fields.

In addition, req.session is generally serialized as JSON by the store
according to http://expressjs.com/en/resources/middleware/session.html.
We can JS JSON to modify those 2 fields.

## 3.4 Exploit Delta: Cooking the Books with Cookies
Based on the code in the "/post_transfer" function, the app would update the database
by using"req.session.account.bitbars". Similarly to 3.3, we can overwrite the value
of "req.session.account.bitbars" to forge Bitbars.

As the grader will send 1 Bitbar to another user and then verify the new account contains 1 million Bitbars,
we need to set the value as 1 million and 1 Bitbars.

## 3.5 Exploit Echo: SQL Injection
Based on the code in the "/post_register" and '/close' functions,
the app doesn't validate or sanitize user's input, which allows SQL injection.

We can use SQL LIKE operator (https://www.w3schools.com/sql/sql_like.asp) to remove the malicious account
and the user3 account after click on "Close".

The SQL code would become the following code, which remove "user3"
and any username that container "username" (i.e. the malicious account).
```
DELETE FROM Users WHERE username == "user3" OR username LIKE "%username%";
```

## 3.6 Exploit Foxtrot: Profile Worm


## 3.7 Exploit Gamma: Password Extraction via Timing Attack