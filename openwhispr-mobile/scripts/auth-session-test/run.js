// Host integration test: real auth wrapper, Better Auth client and Expo plugin.
// Only native storage/platform services and the HTTP response are substitutes.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const ts = require('typescript');
const root = path.resolve(__dirname, '../..');
const Platform = { OS: 'android' };
const native = {
  'react-native': { Platform, AppState: { addEventListener: () => ({ remove() {} }) } },
  'expo-constants': { default: { expoConfig: { scheme: 'openwhispr' } }, __esModule: true },
  'expo-linking': { createURL: () => 'openwhispr://' },
};
function load(file, replacements, sourceFile = file) {
  const localRequire = createRequire(file);
  const compiled = ts.transpileModule(fs.readFileSync(sourceFile, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    fileName: file,
  }).outputText;
  const module = { exports: {} };
  vm.runInThisContext(`(function(require,module,exports){${compiled}\n})`, { filename: file })(
    (name) => (Object.hasOwn(replacements, name) ? replacements[name] : localRequire(name)),
    module,
    module.exports,
  );
  return module.exports;
}
const expo = load(require.resolve('@better-auth/expo/client'), native);
const user = {
  id: 'fixture-user',
  email: 'fixture@example.invalid',
  emailVerified: true,
  isAnonymous: false,
  name: undefined,
};
const initial = {
  user,
  session: {
    id: 'fixture-session',
    userId: user.id,
    token: 'fixture-token',
    expiresAt: new Date(Date.now() + 60000).toISOString(),
  },
};
const cookie = JSON.stringify({
  'better-auth.session_token': { value: 'fixture-token.signature', expires: null },
});
const originalFetch = global.fetch;
const outcomes = [];
async function checkFreshLogin({ platform = 'android', sessionAvailable = true } = {}) {
  Platform.OS = platform;
  const values = new Map();
  const storage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    deleteItemAsync: async (key) => values.delete(key),
  };
  let restarted = false;
  global.fetch = async (input) => {
    const pathname = new URL(input instanceof global.Request ? input.url : input).pathname;
    if (pathname.endsWith('/sign-in/email')) {
      // Email login returns a user and token, not the full session cache shape.
      return new global.Response(
        JSON.stringify({ user, token: initial.session.token, redirect: false }),
        {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'set-cookie': 'better-auth.session_token=fixture-token.signature; Path=/; HttpOnly',
          },
        },
      );
    }
    assert.ok(pathname.endsWith('/get-session'), pathname);
    return !restarted && sessionAvailable
      ? new global.Response(JSON.stringify(initial), {
          headers: { 'content-type': 'application/json' },
        })
      : new global.Response('<title>Gateway</title>', { headers: { 'content-type': 'text/html' } });
  };
  const loadAuth = () =>
    load(
      path.join(root, 'src/lib/authClient.ts'),
      {
        ...native,
        '@better-auth/expo/client': expo,
        'expo-application': { applicationId: 'com.gizmolabs.openwhispr' },
        'expo-secure-store': storage,
        './sessionFetch': { sessionFetch: global.fetch },
        './apiClient': { getClientVersionHeader: () => 'test' },
      },
      process.argv[2],
    );
  const auth = loadAuth();
  const result = await auth.signInWithEmail(user.email, 'fixture-password');
  assert.deepEqual(result.user, user, 'login still succeeds');
  assert.equal(result.error, null);
  restarted = true;
  const restartedAuth = loadAuth();
  const expected = platform === 'android' && sessionAvailable ? user : null;
  assert.deepEqual(
    await restartedAuth.getSession({ allowOfflineCache: true }),
    expected,
    'fresh login must survive a later gateway outage without relying on in-memory identity',
  );
  outcomes.push(`${platform} fresh email login, session available: ${sessionAvailable}`);
}
async function check(
  name,
  {
    platform = 'android',
    status = 200,
    contentType = 'text/html; charset=utf-8',
    body = '<title>Gateway</title>',
    cache = initial,
    allowOfflineCache = true,
    expected = user,
    throws = false,
  } = {},
) {
  Platform.OS = platform;
  const values = new Map([
    ['openwhispr_cookie', cookie],
    ['openwhispr_session_data', JSON.stringify(cache)],
  ]);
  const storage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    deleteItemAsync: async (key) => values.delete(key),
  };
  global.fetch = async () =>
    new global.Response(body, { status, headers: { 'content-type': contentType } });
  const auth = load(
    path.join(root, 'src/lib/authClient.ts'),
    {
      ...native,
      '@better-auth/expo/client': expo,
      'expo-application': { applicationId: 'com.gizmolabs.openwhispr' },
      'expo-secure-store': storage,
      './sessionFetch': { sessionFetch: global.fetch },
      './apiClient': { getClientVersionHeader: () => 'test' },
    },
    process.argv[2],
  );
  if (throws) await assert.rejects(auth.getSession({ allowOfflineCache }), TypeError);
  else assert.deepEqual(await auth.getSession({ allowOfflineCache }), expected, name);
  assert.equal(values.get('openwhispr_cookie'), cookie, `${name}: cookie preserved`);
  if (platform === 'android' && status === 200 && contentType.startsWith('text/html')) {
    assert.equal(
      values.get('openwhispr_session_data'),
      JSON.stringify(cache),
      `${name}: gateway must not overwrite cache`,
    );
  }
  if (platform === 'android' && (status === 401 || status === 403 || body === 'null')) {
    assert.equal(
      values.has('openwhispr_session_data'),
      false,
      `${name}: authoritative sign-out clears identity`,
    );
  }
  outcomes.push(name);
}
(async () => {
  try {
    await checkFreshLogin();
    await checkFreshLogin({ sessionAvailable: false });
    await checkFreshLogin({ platform: 'ios' });
    await check('Android gateway preserves matching cache');
    await check('Explicit validation rejects gateway', { allowOfflineCache: false, throws: true });
    await check('iOS behavior unchanged', { platform: 'ios', expected: null });
    await check('Authoritative signed-out JSON', {
      contentType: 'application/json',
      body: 'null',
      expected: null,
    });
    await check('Rejected401', {
      status: 401,
      contentType: 'application/json',
      body: '{}',
      expected: null,
    });
    await check('Rejected403', {
      status: 403,
      contentType: 'application/json',
      body: '{}',
      expected: null,
    });
    await check('Transient503', { status: 503 });
    await check('Expired cache not restored', {
      cache: { ...initial, session: { ...initial.session, expiresAt: '2000-01-01T00:00:00Z' } },
      expected: null,
    });
    await check('Different cookie not restored', {
      cache: { ...initial, session: { ...initial.session, token: 'other-token' } },
      expected: null,
    });
    const online = { ...user, id: 'current-user' };
    await check('Online identity wins', {
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify({ ...initial, user: online }),
      expected: online,
    });
    console.log(JSON.stringify({ passed: outcomes.length, outcomes }));
  } finally {
    global.fetch = originalFetch;
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
