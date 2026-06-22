document.getElementById('splash-screen').addEventListener('click', function () {
    this.classList.add('fade-out');
    setTimeout(function () {
        window.location.href = 'main.html';
    }, 800);
});
