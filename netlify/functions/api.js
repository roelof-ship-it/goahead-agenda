const admin = require('firebase-admin');

const PROJECT_ID    = process.env.FIREBASE_PROJECT_ID;
const CLIENT_EMAIL  = process.env.FIREBASE_CLIENT_EMAIL;
const PRIVATE_KEY   = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId:   PROJECT_ID,
      clientEmail: CLIENT_EMAIL,
      privateKey:  PRIVATE_KEY
    })
  });
}

const db = admin.firestore();
const DATA_DOC = db.collection('agenda').doc('data');

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
  'Content-Type': 'application/json'
};

async function loadData() {
  const snap = await DATA_DOC.get();
  if (!snap.exists) {
    return { bookings: [], users: [] };
  }
  const data = snap.data() || {};
  return {
    bookings: Array.isArray(data.bookings) ? data.bookings : [],
    users:    Array.isArray(data.users)    ? data.users    : []
  };
}

async function saveData(bookings, users) {
  await DATA_DOC.set({ bookings, users }, { merge: false });
}

exports.handler = async function(event) {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS, body: '' };
  }

  if (!PROJECT_ID || !CLIENT_EMAIL || !PRIVATE_KEY) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'Firebase niet geconfigureerd' }) };
  }

  try {
    const method = event.httpMethod;

    if (method === 'GET') {
      const { bookings, users } = await loadData();
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
      const current = await loadData();
      let updatedUsers = current.users;

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

      const bookings = Array.isArray(body.bookings) ? body.bookings : current.bookings;
      await saveData(bookings, updatedUsers);

      const safeUsers = updatedUsers.map(function(u) { return { name: u.name, role: u.role }; });
      return {
        statusCode: 200,
        headers: CORS,
        body: JSON.stringify({ ok: true, users: safeUsers })
      };
    }

    if (method === 'POST') {
      const body = JSON.parse(event.body || '{}');
      const current = await loadData();
      let storedUsers = current.users;

      if (storedUsers.length === 0 && body.action === 'login' && (body.name || '').toLowerCase() === 'admin') {
        storedUsers.push({ name: 'Admin', pw: body.pw, role: 'admin' });
        await saveData(current.bookings, storedUsers);
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
        await saveData(current.bookings, storedUsers);
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
