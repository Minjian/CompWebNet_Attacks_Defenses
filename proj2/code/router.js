import express from 'express';
import sqlite from 'sqlite';

import { asyncMiddleware } from './utils/asyncMiddleware';
import sleep from './utils/sleep';
import { generateRandomness, HMAC, KDF, checkPassword } from './utils/crypto';

const router = express.Router();
const dbPromise = sqlite.open('./db/database.sqlite')

// Defense Alpha
function sanitized_string(input) {
  if (typeof input !== 'string') return input;
  const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      "/": '&#x2F;',
  };
  const reg = /[&<>"'/]/ig;
  return input.replace(reg, (match)=>(map[match]));
}
function sanitized_object(object) {
  if (typeof object === 'undefined' || object === null) return object;
  object.username = sanitized_string(object.username);
  object.profile = sanitized_string(object.profile);
  return object;
}

// Defense Bravo
// Change transfer server secret key every 5 minutes
const transfer_secret_key_timeout_ms = 300000;
var transfer_server_secret_key = generateRandomness();
setInterval(function() {transfer_server_secret_key = generateRandomness()}, transfer_secret_key_timeout_ms);
function generate_transfer_token(account) {
  if (typeof account === 'undefined' || account === null) return account;
  return HMAC(transfer_server_secret_key, account.username.concat(account.hashedPassword));
}

// Defense Charlie
var login_session_signature = null;
const session_server_secret_key = generateRandomness();
function generate_session_signature(session) {
  if (typeof session.account.username === 'undefined' || session.account.username === null) return null;
  return HMAC(session_server_secret_key, session.account.username.concat(session.account.hashedPassword));
}
function force_logout(req, res, next) {
  req.session.loggedIn = false;
  req.session.account = {};
  login_session_signature = null;
  render(req, res, next, 'index', 'Bitbar Home', 'Logged out due to a security reason! Please login again.');
}

function render(req, res, next, page, title, errorMsg = false, result = null) {
  res.render(
    'layout/template', {
      page,
      title: sanitized_string(title),
      loggedIn: req.session.loggedIn,
      account: sanitized_object(req.session.account),
      errorMsg: sanitized_string(errorMsg),
      result: sanitized_object(result),
    }
  );
}


router.get('/', (req, res, next) => {
  if(generate_session_signature(req.session) !== login_session_signature) {
    force_logout(req, res, next);
  }
  render(req, res, next, 'index', 'Bitbar Home');
});


router.post('/set_profile', asyncMiddleware(async (req, res, next) => {
  if(generate_session_signature(req.session) !== login_session_signature) {
    force_logout(req, res, next);
  }

  req.session.account.profile = req.body.new_profile;
  console.log(req.body.new_profile);
  const db = await dbPromise;
  const query = `UPDATE Users SET profile = ? WHERE username = "${req.session.account.username}";`;
  const result = await db.run(query, req.body.new_profile);
  render(req, res, next, 'index', 'Bitbar Home');

}));


router.get('/login', (req, res, next) => {
  render(req, res, next, 'login/form', 'Login');
});


router.get('/get_login', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
  const result = await db.get(query);
  if(result) { // if this username actually exists
    if(checkPassword(req.query.password, result)) { // if password is valid
      await sleep(2000);
      req.session.loggedIn = true;
      req.session.account = result;
      login_session_signature = generate_session_signature(req.session);
      render(req, res, next, 'login/success', 'Bitbar Home');
      return;
    }
  }
  render(req, res, next, 'login/form', 'Login', 'This username and password combination does not exist!');
}));


router.get('/register', (req, res, next) => {
  render(req, res, next, 'register/form', 'Register');
});


router.post('/post_register', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == "${req.body.username}";`;
  let result = await db.get(query);
  if(result) { // query returns results
    if(result.username === req.body.username) { // if username exists
      render(req, res, next, 'register/form', 'Register', 'This username already exists!');
      return;
    }
  }
  const salt = generateRandomness();
  const hashedPassword = KDF(req.body.password, salt);
  console.log(hashedPassword);
  console.log(salt);
  query = `INSERT INTO Users(username, hashedPassword, salt, profile, bitbars) VALUES(?, ?, ?, ?, ?)`;
  await db.run(query, [req.body.username, hashedPassword, salt, '', 100]);
  req.session.loggedIn = true;
  req.session.account = {
    username: req.body.username,
    hashedPassword,
    salt,
    profile: '',
    bitbars: 100,
  };
  login_session_signature = generate_session_signature(req.session);
  render(req, res, next,'register/success', 'Bitbar Home');
}));


router.get('/close', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(generate_session_signature(req.session) !== login_session_signature) {
    force_logout(req, res, next);
  }

  const db = await dbPromise;
  const query = `DELETE FROM Users WHERE username == "${req.session.account.username}";`;
  await db.get(query);
  req.session.loggedIn = false;
  req.session.account = {};
  login_session_signature = null;
  render(req, res, next, 'index', 'Bitbar Home', 'Deleted account successfully!');
}));


router.get('/logout', (req, res, next) => {
  req.session.loggedIn = false;
  req.session.account = {};
  login_session_signature = null;
  render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
});


router.get('/profile', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(generate_session_signature(req.session) !== login_session_signature) {
    force_logout(req, res, next);
  }

  if(req.query.username != null) { // if visitor makes a search query
    const db = await dbPromise;
    const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
    let result;
    try {
      result = await db.get(query);
    } catch(err) {
      result = false;
    }
    if(result) { // if user exists
      render(req, res, next, 'profile/view', 'View Profile', false, result);
    }
    else { // user does not exist
      render(req, res, next, 'profile/view', 'View Profile', `${req.query.username} does not exist!`, req.session.account);
    }
  } else { // visitor did not make query, show them their own profile
    render(req, res, next, 'profile/view', 'View Profile', false, req.session.account);
  }
}));


router.get('/transfer', (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(generate_session_signature(req.session) !== login_session_signature) {
    force_logout(req, res, next);
  }

  render(req, res, next, 'transfer/form', 'Transfer Bitbars', false,
         {receiver:null, amount:null, transfer_token:generate_transfer_token(req.session.account)});
});


router.post('/post_transfer', asyncMiddleware(async(req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(generate_session_signature(req.session) !== login_session_signature) {
    force_logout(req, res, next);
  }

  if(req.body.destination_username === req.session.account.username) {
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'You cannot send money to yourself!',
           {receiver:null, amount:null, transfer_token:generate_transfer_token(req.session.account)});
    return;
  }

  if(req.body.transfer_token !== generate_transfer_token(req.session.account)) {
    render(req, res, next, 'transfer/form', 'Transfer Bitbars',
           'Transfer Session Expired! Please try again within '.concat(transfer_secret_key_timeout_ms/60000).concat(" minutes"),
           {receiver:null, amount:null, transfer_token:generate_transfer_token(req.session.account)});
    return;
  }

  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == "${req.body.destination_username}";`;
  const receiver = await db.get(query);
  if(receiver) { // if user exists
    const amount = parseInt(req.body.quantity);
    if(Number.isNaN(amount) || amount > req.session.account.bitbars || amount < 1) {
      render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Invalid transfer amount!',
             {receiver:null, amount:null, transfer_token:generate_transfer_token(req.session.account)});
      return;
    }

    req.session.account.bitbars -= amount;
    query = `UPDATE Users SET bitbars = "${req.session.account.bitbars}" WHERE username == "${req.session.account.username}";`;
    await db.exec(query);
    const receiverNewBal = receiver.bitbars + amount;
    query = `UPDATE Users SET bitbars = "${receiverNewBal}" WHERE username == "${receiver.username}";`;
    await db.exec(query);
    render(req, res, next, 'transfer/success', 'Transfer Complete', false,
           {receiver, amount, transfer_token:generate_transfer_token(req.session.account)});
  } else { // user does not exist
    let q = req.body.destination_username;
    if (q == null) q = '';

    let oldQ;
    while (q !== oldQ) {
      oldQ = q;
      q = q.replace(/script|SCRIPT|img|IMG/g, '');
    }
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', `User ${q} does not exist!`,
           {receiver:null, amount:null, transfer_token:generate_transfer_token(req.session.account)});
  }
}));


router.get('/steal_cookie', (req, res, next) => {
  let stolenCookie = req.query.cookie;
  console.log('\n\n' + stolenCookie + '\n\n');
  render(req, res, next, 'theft/view_stolen_cookie', 'Cookie Stolen!', false, stolenCookie);
});

router.get('/steal_password', (req, res, next) => {
  let password = req.query.password;
  let timeElapsed = req.query.timeElapsed;
  console.log(`\n\nPassword: ${req.query.password}, time elapsed: ${req.query.timeElapsed}\n\n`);
  res.end();
});


module.exports = router;
