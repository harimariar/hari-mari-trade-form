// netlify/functions/trade-reference.js
//
// Bridges the public form to your private NetSuite RESTlet. Holds your
// NetSuite Token-Based Authentication credentials server-side (as Netlify
// environment variables) so they never reach the browser.

const crypto = require('crypto');
const OAuth = require('oauth-1.0a');

const oauth = OAuth({
  consumer: {
    key: process.env.NS_CONSUMER_KEY,
    secret: process.env.NS_CONSUMER_SECRET
  },
  signature_method: 'HMAC-SHA256',
  hash_function(base_string, key) {
    return crypto.createHmac('sha256', key).update(base_string).digest('base64');
  }
});

const token = {
  key: process.env.NS_TOKEN_ID,
  secret: process.env.NS_TOKEN_SECRET
};

const RESTLET_URL = process.env.NS_RESTLET_URL;
const REALM = process.env.NS_ACCOUNT_ID;

exports.handler = async (event) => {
  try {
    let method, url, payload;

    if (event.httpMethod === 'GET') {
      const t = event.queryStringParameters && event.queryStringParameters.t;
      if (!t) {
        return jsonResponse(400, { found: false, error: 'Missing token' });
      }
      method = 'GET';
      url = RESTLET_URL + '&t=' + encodeURIComponent(t);
      payload = undefined;
    } else if (event.httpMethod === 'POST') {
      method = 'POST';
      url = RESTLET_URL;
      payload = event.body ? JSON.parse(event.body) : {};
      if (!payload.t) {
        return jsonResponse(400, { success: false, error: 'Missing token' });
      }
    } else {
      return jsonResponse(405, { error: 'Method not allowed' });
    }

    const authHeader = oauth.toHeader(oauth.authorize({ url, method }, token));
    authHeader.Authorization += `, realm="${REALM}"`;

    const nsResponse = await fetch(url, {
      method,
      headers: {
        Authorization: authHeader.Authorization,
        'Content-Type': 'application/json'
      },
      body: method === 'POST' ? JSON.stringify(payload) : undefined
    });

    const nsJson = await nsResponse.json();
    return jsonResponse(200, nsJson);
  } catch (err) {
    return jsonResponse(500, { success: false, error: 'Server error contacting NetSuite.' });
  }
};

function jsonResponse(statusCode, body) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  };
}
