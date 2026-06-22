 const scanName = "{{ data.scanname }}";
    document.getElementById('scanForm').addEventListener('submit', function(event) {
    event.preventDefault();

    const sh = document.querySelector('input[name="shell"]:checked').value;
    const de = document.getElementById('depth').value;
    const o = document.getElementById('os').value;
    const thr = document.getElementById('threads').value;
    const file = document.getElementById('filename').value;


    const data = {
        shell:sh,
        depth:de,
        os:o,
        threads:thr,
        filename:file
    };

    fetch($`/scan/${scanName}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        console.log('Ответ от сервера:', data);
        alert('Данные успешно отправлены!');
    })
    .catch(error => {

        alert('Произошла ошибка при отправке данных.');
    });
});