
function togglePayloadField() {
    const method = document.getElementById('method').value;
    const payloadField = document.getElementById('payload');


    if (method === 'GET' || method === 'DELETE') {
        payloadField.disabled = true;
        payloadField.placeholder = 'Тело запроса не используется для GET и DELETE';
    } else {
        payloadField.disabled = false;
        payloadField.placeholder = 'Тело запроса';
    }
}
document.getElementById('method').addEventListener('change', togglePayloadField);
document.addEventListener('DOMContentLoaded', togglePayloadField);