  document.getElementById('addHeader').addEventListener('click', function () {
    const headersContainer = document.getElementById('headersContainer');
    const headerInput = document.createElement('div');
    headerInput.className = 'header-input';
    headerInput.innerHTML = `
        <input type="text" placeholder="Заголовок" class="header-name">
        <input type="text" placeholder="Значение" class="header-value">
        <button type="button" class="remove-header">Удалить</button>
    `;
    headersContainer.appendChild(headerInput);
    headerInput.querySelector('.remove-header').addEventListener('click', function () {
        headersContainer.removeChild(headerInput);
    });
});