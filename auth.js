const OIDC_ISSUER = 'https://auth.acropolebrasil.com.br/as/realms/oinabnb';
const OIDC_CLIENT_ID = 'gaf';
const OIDC_SCOPE = 'openid profile email';
const TOKEN_STORAGE_KEY = 'gaf.oidc.tokens';
const LOGIN_STORAGE_KEY = 'gaf.oidc.login';
const RETURN_TO_STORAGE_KEY = 'gaf.oidc.returnTo';
const authScriptUrl = document.currentScript?.src || new URL('auth.js', window.location.href).href;
const APP_BASE_PATH = new URL('.', authScriptUrl).pathname;

function getRedirectUri() {
    if (window.location.protocol !== 'http:' && window.location.protocol !== 'https:') {
        throw new Error('Abra o site por HTTPS ou por um servidor local HTTP; login não funciona abrindo o arquivo diretamente.');
    }

    return new URL(APP_BASE_PATH, window.location.origin).href;
}

function encodeBase64Url(bytes) {
    const byteArray = new Uint8Array(bytes);
    let binary = '';
    byteArray.forEach(byte => binary += String.fromCharCode(byte));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBase64Url(value) {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    return Uint8Array.from(atob(padded), character => character.charCodeAt(0));
}

function decodeJwtPart(value) {
    return JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));
}

function createRandomValue() {
    return encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

function getStoredTokens() {
    try {
        return JSON.parse(sessionStorage.getItem(TOKEN_STORAGE_KEY) || 'null');
    } catch (error) {
        console.error('Não foi possível ler os dados da sessão OIDC.', error);
        sessionStorage.removeItem(TOKEN_STORAGE_KEY);
        return null;
    }
}

function isAuthenticated() {
    const tokens = getStoredTokens();
    return Boolean(tokens?.accessToken && tokens.expiresAt > Date.now() / 1000);
}

function saveReturnTo(url) {
    const requestedUrl = new URL(url, window.location.origin);
    const appRoot = new URL(APP_BASE_PATH, window.location.origin);

    if (requestedUrl.origin === window.location.origin && requestedUrl.pathname.startsWith(appRoot.pathname)) {
        sessionStorage.setItem(RETURN_TO_STORAGE_KEY, `${requestedUrl.pathname}${requestedUrl.search}${requestedUrl.hash}`);
    } else {
        sessionStorage.setItem(RETURN_TO_STORAGE_KEY, 'etapas.html');
    }
}

function getReturnTo() {
    const savedUrl = sessionStorage.getItem(RETURN_TO_STORAGE_KEY) || 'etapas.html';
    const appRoot = new URL(APP_BASE_PATH, window.location.origin);
    const requestedUrl = new URL(savedUrl, appRoot);
    sessionStorage.removeItem(RETURN_TO_STORAGE_KEY);

    if (requestedUrl.origin !== window.location.origin || !requestedUrl.pathname.startsWith(appRoot.pathname)) {
        return new URL('etapas.html', appRoot).href;
    }

    return requestedUrl.href;
}

function requireAuthentication() {
    if (isAuthenticated()) {
        return true;
    }

    saveReturnTo(window.location.href);
    window.location.replace(getRedirectUri());
    return false;
}

async function loadProviderMetadata() {
    const response = await fetch(`${OIDC_ISSUER}/.well-known/openid-configuration`);
    if (!response.ok) {
        throw new Error(`Não foi possível carregar a configuração OIDC (${response.status}).`);
    }

    const metadata = await response.json();
    if (metadata.issuer !== OIDC_ISSUER || !metadata.authorization_endpoint || !metadata.token_endpoint || !metadata.jwks_uri) {
        throw new Error('A configuração OIDC do provedor está incompleta ou não corresponde ao issuer esperado.');
    }

    return metadata;
}

async function validateIdToken(idToken, nonce, metadata) {
    const parts = idToken.split('.');
    if (parts.length !== 3) {
        throw new Error('O provedor retornou um ID token inválido.');
    }

    const header = decodeJwtPart(parts[0]);
    const claims = decodeJwtPart(parts[1]);
    const keyResponse = await fetch(metadata.jwks_uri);
    if (!keyResponse.ok) {
        throw new Error(`Não foi possível carregar as chaves de assinatura OIDC (${keyResponse.status}).`);
    }

    const keySet = await keyResponse.json();
    const signingKey = keySet.keys?.find(key => key.kid === header.kid && key.use !== 'enc');
    if (!signingKey) {
        throw new Error('Não foi encontrada a chave para validar o ID token.');
    }

    let algorithm;
    let importAlgorithm;
    if (header.alg === 'RS256') {
        algorithm = { name: 'RSASSA-PKCS1-v1_5' };
        importAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    } else if (header.alg === 'PS256') {
        algorithm = { name: 'RSA-PSS', saltLength: 32 };
        importAlgorithm = { name: 'RSA-PSS', hash: 'SHA-256' };
    } else if (header.alg === 'ES256') {
        algorithm = { name: 'ECDSA', hash: 'SHA-256' };
        importAlgorithm = { name: 'ECDSA', namedCurve: 'P-256' };
    } else {
        throw new Error(`O algoritmo de assinatura OIDC ${header.alg} não é suportado.`);
    }

    const publicKey = await crypto.subtle.importKey('jwk', signingKey, importAlgorithm, false, ['verify']);
    const signedContent = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const signatureIsValid = await crypto.subtle.verify(algorithm, publicKey, decodeBase64Url(parts[2]), signedContent);
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];

    const now = Date.now() / 1000;
    if (!signatureIsValid ||
        claims.iss !== OIDC_ISSUER ||
        !audiences.includes(OIDC_CLIENT_ID) ||
        (audiences.length > 1 && claims.azp !== OIDC_CLIENT_ID) ||
        (claims.azp && claims.azp !== OIDC_CLIENT_ID) ||
        claims.nonce !== nonce ||
        typeof claims.sub !== 'string' ||
        typeof claims.iat !== 'number' ||
        claims.iat > now + 60 ||
        typeof claims.exp !== 'number' ||
        claims.exp <= now) {
        throw new Error('Não foi possível validar a identidade retornada pelo provedor.');
    }
}

async function startLogin() {
    const metadata = await loadProviderMetadata();
    const verifier = createRandomValue();
    const nonce = createRandomValue();
    const state = createRandomValue();
    const challenge = encodeBase64Url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));

    sessionStorage.setItem(LOGIN_STORAGE_KEY, JSON.stringify({ verifier, nonce, state }));

    const authorizationUrl = new URL(metadata.authorization_endpoint);
    authorizationUrl.search = new URLSearchParams({
        client_id: OIDC_CLIENT_ID,
        redirect_uri: getRedirectUri(),
        response_type: 'code',
        scope: OIDC_SCOPE,
        state,
        nonce,
        code_challenge: challenge,
        code_challenge_method: 'S256'
    }).toString();

    window.location.assign(authorizationUrl.href);
}

async function finishLogin() {
    const callbackUrl = new URL(window.location.href);
    const authorizationError = callbackUrl.searchParams.get('error');
    if (authorizationError) {
        throw new Error(callbackUrl.searchParams.get('error_description') || `Autenticação recusada (${authorizationError}).`);
    }

    const code = callbackUrl.searchParams.get('code');
    const returnedState = callbackUrl.searchParams.get('state');
    const pendingLogin = JSON.parse(sessionStorage.getItem(LOGIN_STORAGE_KEY) || 'null');
    if (!code || !pendingLogin || returnedState !== pendingLogin.state) {
        throw new Error('A resposta de autenticação é inválida ou expirou. Tente entrar novamente.');
    }

    const metadata = await loadProviderMetadata();
    const tokenResponse = await fetch(metadata.token_endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: OIDC_CLIENT_ID,
            code,
            redirect_uri: getRedirectUri(),
            code_verifier: pendingLogin.verifier
        })
    });

    if (!tokenResponse.ok) {
        throw new Error(`A troca do código de autenticação falhou (${tokenResponse.status}).`);
    }

    const tokenResponseBody = await tokenResponse.json();
    const expiresIn = Number(tokenResponseBody.expires_in);
    if (!tokenResponseBody.access_token ||
        !tokenResponseBody.id_token ||
        !Number.isFinite(expiresIn) ||
        expiresIn <= 0) {
        throw new Error('O provedor retornou uma resposta de autenticação incompleta.');
    }

    await validateIdToken(tokenResponseBody.id_token, pendingLogin.nonce, metadata);
    sessionStorage.setItem(TOKEN_STORAGE_KEY, JSON.stringify({
        accessToken: tokenResponseBody.access_token,
        idToken: tokenResponseBody.id_token,
        expiresAt: Date.now() / 1000 + expiresIn
    }));
    sessionStorage.removeItem(LOGIN_STORAGE_KEY);
}

function showLoginError(message) {
    const errorElement = document.getElementById('login-error');
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.hidden = false;
    }
}

async function initializeLoginPage() {
    const callbackUrl = new URL(window.location.href);
    const isCallback = callbackUrl.searchParams.has('code') || callbackUrl.searchParams.has('error');
    const loginButton = document.getElementById('login-button');
    const loginButtonLabel = document.getElementById('login-button-label');

    if (isCallback) {
        if (loginButton) {
            loginButton.disabled = true;
            loginButtonLabel.textContent = 'Validando...';
        }

        try {
            await finishLogin();
            window.location.replace(getReturnTo());
            return;
        } catch (error) {
            console.error('Falha ao concluir a autenticação OIDC.', error);
            sessionStorage.removeItem(LOGIN_STORAGE_KEY);
            showLoginError(error instanceof Error ? error.message : 'Não foi possível concluir o login.');
            window.history.replaceState({}, document.title, getRedirectUri());
        } finally {
            if (loginButton) {
                loginButton.disabled = false;
                loginButtonLabel.textContent = 'Entrar com o Login Acrópole';
            }
        }
    } else if (isAuthenticated()) {
        window.location.replace(getReturnTo());
        return;
    }

    if (loginButton) {
        loginButton.addEventListener('click', async () => {
            loginButton.disabled = true;
            loginButtonLabel.textContent = 'Conectando...';
            try {
                await startLogin();
            } catch (error) {
                console.error('Falha ao iniciar a autenticação OIDC.', error);
                showLoginError(error instanceof Error ? error.message : 'Não foi possível iniciar o login.');
                loginButton.disabled = false;
                loginButtonLabel.textContent = 'Entrar com o Login Acrópole';
            }
        });
    }
}
