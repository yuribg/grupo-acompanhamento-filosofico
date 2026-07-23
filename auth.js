const STORAGE_KEY = 'autenticado';
const LOGIN_PAGE = '/index.html';
const ETAPAS_PAGE = '/etapas.html';
const SENHA_ACESSO = 'gaf7353U';

function isAuthenticated() {
    return sessionStorage.getItem(STORAGE_KEY) === 'true';
}

function setAuthenticated() {
    sessionStorage.setItem(STORAGE_KEY, 'true');
}

function requireAuthentication() {
    if (!isAuthenticated()) {
        window.location.href = LOGIN_PAGE;
    }
}

function validateLogin(event) {
    event.preventDefault();

    const passwordInput = document.getElementById('password-input');
    const errorMessage = document.getElementById('login-error');

    if (passwordInput.value === SENHA_ACESSO) {
        setAuthenticated();
        window.location.href = ETAPAS_PAGE;
    } else {
        errorMessage.style.display = 'block';
        passwordInput.value = '';
        passwordInput.focus();

        setTimeout(() => {
            errorMessage.style.display = 'none';
        }, 3000);
    }
}