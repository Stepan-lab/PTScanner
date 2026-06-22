
document.getElementById('addCookie').addEventListener('click', function () {
    const cookiesContainer = document.getElementById('cookiesContainer');
    const cookieInput = document.createElement('div');
    cookieInput.className = 'cookie-input';
    cookieInput.innerHTML = `
        <input type="text" placeholder="Куки" class="cookie-name">
        <input type="text" placeholder="Значение" class="cookie-value">
        <button type="button" class="remove-cookie">Удалить</button>
    `;
    cookiesContainer.appendChild(cookieInput);


    cookieInput.querySelector('.remove-cookie').addEventListener('click', function () {
        cookiesContainer.removeChild(cookieInput);
    });
});


function getCookies() {
    const cookies = {};
    const cookieInputs = document.querySelectorAll('.cookie-input');
    cookieInputs.forEach(cookie => {
        const name = cookie.querySelector('.cookie-name').value;
        const value = cookie.querySelector('.cookie-value').value;
        if (name && value) {
            cookies[name] = value;
        }
    });
    return cookies;
}