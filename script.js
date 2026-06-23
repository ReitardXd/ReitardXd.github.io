// splash screen 
const splash = document.getElementById('splash-screen');

if (splash) {
    setTimeout(function () {
        splash.classList.add('fade-out');
        setTimeout(function () {
            window.location.href = 'main.html';
        }, 800);
    }, 3000);


}
