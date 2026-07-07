// netlify/functions/trade-reference.js
//
// Bridges the public form to your private NetSuite RESTlet. Holds your
// NetSuite Token-Based Authentication credentials server-side (as Netlify
// environment variables) so they never reach the browser.
//
// SETUP REQUIRED:
// 1. In your Netlify site repo: npm install oauth-1.0a
//    (Node 18+ is assumed for global fetch - Netlify's default runtime
//    supports this; no extra HTTP library needed.)
// 2. In Netlify's dashboard (Site settings > Environment variables), add:
//      NS_ACCOUNT_ID       e.g. 3950416
//      NS_CONSUMER_KEY     from your NetSuite Integration record
//      NS_CONSUMER_SECRET  from your NetSuite Integration record
//      NS_TOKEN_ID         from your NetSuite Access Token
//      NS_TOKEN_SECRET     from your NetSuite Access Token
//      NS_RESTLET_URL      e.g.
//        https://3950416.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=123&deploy=1
//        (script= and deploy= come from the RESTlet's deployment page)
// 3. Place this file at netlify/functions/trade-reference.js in your site
//    repo, then deploy. It'll be reachable at:
//        https://yoursite.netlify.app/.netlify/functions/trade-reference
 
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
 
    let nsJson;
    try {
      nsJson = await nsResponse.json();
    } catch (parseErr) {
      return jsonResponse(nsResponse.status, {
        success: false,
        found: false,
        error: 'NetSuite returned an unreadable response (status ' + nsResponse.status + ').'
      });
    }
 
    // NetSuite's own error format looks like {"error": {"code": "...", "message": "..."}}
    // rather than our {success, error} shape - normalize it so the client
    // always gets a plain string to display, never a raw object.
    if (nsJson && nsJson.error && typeof nsJson.error === 'object') {
      const msg = nsJson.error.message || nsJson.error.code || 'NetSuite rejected the request.';
      return jsonResponse(nsResponse.status, { success: false, found: false, error: msg });
    }
 
    return jsonResponse(nsResponse.status, nsJson);
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
