document.getElementById('requestForm').addEventListener('submit', function (e) {
    e.preventDefault();


    const method = document.getElementById('method').value;
    const url = document.getElementById('url').value;
    const payload = document.getElementById('payload').value;
    const sn = document.getElementById('scanname').value;


    const headers = {};
    const headerInputs = document.querySelectorAll('.header-input');
    headerInputs.forEach(header => {
        const name = header.querySelector('.header-name').value;
        const value = header.querySelector('.header-value').value;
        if (name && value) {
            headers[name] = value;
        }
    });


    const cookies = {};
    const cookieInputs = document.querySelectorAll('.cookie-input');
    cookieInputs.forEach(cookie => {
        const name = cookie.querySelector('.cookie-name').value;
        const value = cookie.querySelector('.cookie-value').value;
        if (name && value) {
            cookies[name] = value;
        }
    });

    const requestData = {
        url: url,
        scanname:sn,
        method: method,
        headers: headers,
        cookies: cookies,
        payload: payload
    };


    fetch('/scan_settings', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestData)
    })
    .then(response => response.json())
    .then(data => {

        const responseContainer = document.getElementById('response');
        responseContainer.textContent = JSON.stringify(data, null, 2);
        responseContainer.style.display = 'block';


        if (data.redirect_url) {
            window.open(data.redirect_url,'_blank')

        }
    })
    .catch(error => {
        console.error('Ошибка:', error);
        alert('Произошла ошибка при отправке запроса.');
    });
});