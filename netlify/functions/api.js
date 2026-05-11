const https  = require('https');
const crypto = require('crypto');

const BIN_ID         = process.env.JSONBIN_BIN_ID;
const API_KEY        = process.env.JSONBIN_API_KEY;
const ENCRYPT_SECRET = process.env.ENCRYPT_SECRET;

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
  'Content-Type': 'application/json'
};

function jsonbinRequest(method, body) {
  return new Promise(function(resolve, reject) {
    const path    = '/v3/b/' + BIN_ID + (method === 'GET' ? '/latest' : '');
    const payload = body ? JSON.stringify(body) : null;
    const options = {
      hostname: 'api.jsonbin.io',
      path,
      method,
      headers: {
        'X-Master-Key':     API_KEY,
        'X-Access-Key':     API_KEY,
        'X-Bin-Versioning': 'false',
        'Content-Type':     'application/json'
      }
    };
    if (payload) options.headers['Content-Length'] = Buffer.byteLength(payload);

    const req = https.request(options, function(res) {
      let data = '';
      res.on('data', function(c) { data += c; });
      res.on('end',  function()  { resolve({ status: res.statusCode, body: data }); });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function encryptUsers(usersArr) {
  const key = crypto.scryptSync(ENCRYPT_SECRET, 'gak-salt', 32);
  const iv  = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const json = JSON.stringify(usersArr);
  const encrypted = Buffer.concat([cipher.update(json, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function decryptUsers(encoded) {
  const key  = crypto.scryptSync(ENCRYPT_SECRET, 'gak-salt', 32);
  const buf  = Buffer.from(encoded, 'base64');
  const iv   = buf.slice(0, 12);
  const tag  = buf.slice(12, 28);
  const data = buf.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
}

exports.handler = async function(event) {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS, body: '' };
  }

  if (!BIN_ID || !API_KEY || !ENCRYPT_SECRET) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'Server niet geconfigureerd' }) };
  }

  try {
    const method = event.httpMethod;

    if (method === 'GET') {
      const result = await jsonbinRequest('GET');
      const record = JSON.parse(result.body).record || {};
      const bookings = Array.isArray(record.bookings) ? record.bookings : [];

      // Ontsleutel gebruikers server-side — stuur ze NOOIT naar de browser
      let users = [];
      if (typeof record.users === 'string') {
        try {
          users = decryptUsers(record.users);
        } catch(decErr) {
          return {
            statusCode: 500,
            headers: CORS,
            body: JSON.stringify({
              error: 'Kan gebruikersdata niet ontsleutelen. ENCRYPT_SECRET klopt mogelijk niet.'
            })
          };
        }
      } else if (Array.isArray(record.users)) {
        users = record.users;
      }

      // Stuur alleen naam en rol naar de browser, nooit het wachtwoord
      const safeUsers = users.map(function(u) {
        return { name: u.name, role: u.role };
      });

      return {
        statusCode: 200,
        headers: CORS,
        body: JSON.stringify({ bookings, users: safeUsers })
      };
    }

    if (method === 'PUT') {
      const body = JSON.parse(event.body || '{}');

      // Haal volledige gebruikersdata op (met wachtwoorden) uit de bin
      const current = await jsonbinRequest('GET');
      const record  = JSON.parse(current.body).record || {};
      let storedUsers = [];
      let usersLoaded = false;

      if (typeof record.users === 'string') {
        try {
          storedUsers = decryptUsers(record.users);
          usersLoaded = true;
        } catch(decErr) {
          // Versleutelde data kan niet gelezen worden — WEIGER deze opslag
          // om te voorkomen dat gebruikersdata wordt overschreven
          return {
            statusCode: 500,
            headers: CORS,
            body: JSON.stringify({
              error: 'Kan bestaande gebruikersdata niet ontsleutelen. ENCRYPT_SECRET klopt mogelijk niet. Opslag geweigerd om dataverlies te voorkomen.'
            })
          };
        }
      } else if (Array.isArray(record.users)) {
        storedUsers = record.users;
        usersLoaded = true;
      } else {
        // Geen users veld — alleen bootstrap actie toegestaan
        usersLoaded = true;
      }

      // Verwerk gebruikerswijzigingen
      let updatedUsers = storedUsers;
      if (body.userAction) {
        const action = body.userAction;

        if (action.type === 'add') {
          updatedUsers.push({ name: action.name, pw: action.pw, role: action.role });
        }
        if (action.type === 'remove') {
          updatedUsers = updatedUsers.filter(function(u) { return u.name !== action.name; });
        }
        if (action.type === 'promote') {
          updatedUsers = updatedUsers.map(function(u) {
            return u.name === action.name ? { name: u.name, pw: u.pw, role: 'admin' } : u;
          });
        }
        if (action.type === 'demote') {
          updatedUsers = updatedUsers.map(function(u) {
            return u.name === action.name ? { name: u.name, pw: u.pw, role: 'user' } : u;
          });
        }
        if (action.type === 'changepw') {
          updatedUsers = updatedUsers.map(function(u) {
            return u.name === action.name ? { name: u.name, pw: action.pw, role: u.role } : u;
          });
        }
        if (action.type === 'bootstrap') {
          if (updatedUsers.length === 0) {
            updatedUsers.push({ name: 'Admin', pw: action.pw, role: 'admin' });
          }
        }
      }

      const encryptedUsers = encryptUsers(updatedUsers);
      const bookings = Array.isArray(body.bookings) ? body.bookings : record.bookings || [];

      const result = await jsonbinRequest('PUT', { bookings, users: encryptedUsers });
      const safeUsers = updatedUsers.map(function(u) { return { name: u.name, role: u.role }; });

      return {
        statusCode: result.status,
        headers: CORS,
        body: JSON.stringify({ ok: true, users: safeUsers })
      };
    }

    if (method === 'POST') {
      // Login verificatie — wachtwoord nooit terug naar browser
      const body = JSON.parse(event.body || '{}');
      const current = await jsonbinRequest('GET');
      const record  = JSON.parse(current.body).record || {};
      let storedUsers = [];
      if (typeof record.users === 'string') {
        try {
          storedUsers = decryptUsers(record.users);
        } catch(decErr) {
          return {
            statusCode: 500,
            headers: CORS,
            body: JSON.stringify({
              error: 'Kan gebruikersdata niet ontsleutelen. ENCRYPT_SECRET klopt mogelijk niet.'
            })
          };
        }
      } else if (Array.isArray(record.users)) {
        storedUsers = record.users;
      }

      // Bootstrap als geen gebruikers
      if (storedUsers.length === 0 && body.action === 'bootstrap') {
        storedUsers.push({ name: 'Admin', pw: body.pw, role: 'admin' });
        await jsonbinRequest('PUT', {
          bookings: record.bookings || [],
          users: encryptUsers(storedUsers)
        });
        return {
          statusCode: 200,
          headers: CORS,
          body: JSON.stringify({ ok: true, role: 'admin', name: 'Admin' })
        };
      }

      if (body.action === 'login') {
        const user = storedUsers.find(function(u) {
          return u.name.toLowerCase() === (body.name || '').toLowerCase() && u.pw === body.pw;
        });

        // Migreer plaintext wachtwoord als gevonden
        if (user && !user.pw.match(/^[a-f0-9]{64}$/)) {
          // plaintext — laat client hashen, hier niks doen
        }

        if (user) {
          return {
            statusCode: 200,
            headers: CORS,
            body: JSON.stringify({ ok: true, name: user.name, role: user.role })
          };
        } else {
          return {
            statusCode: 401,
            headers: CORS,
            body: JSON.stringify({ ok: false })
          };
        }
      }

      if (body.action === 'register') {
        const exists = storedUsers.find(function(u) {
          return u.name.toLowerCase() === (body.name || '').toLowerCase();
        });
        if (exists) {
          return { statusCode: 409, headers: CORS, body: JSON.stringify({ ok: false, error: 'Naam al in gebruik' }) };
        }
        storedUsers.push({ name: body.name, pw: body.pw, role: 'user' });
        await jsonbinRequest('PUT', {
          bookings: record.bookings || [],
          users: encryptUsers(storedUsers)
        });
        return {
          statusCode: 200,
          headers: CORS,
          body: JSON.stringify({ ok: true, name: body.name, role: 'user' })
        };
      }
    }

    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: 'Method niet toegestaan' }) };

  } catch(err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) };
  }
};
