// Splash screen: auto-enter after a short pause, or let visitors skip it.
const splash = document.getElementById('splash-screen');

if (splash) {
    const AUTO_DELAY_MS = 2000;
    const FADE_DURATION_MS = 800;
    let leaving = false;

    function enterSite() {
        if (leaving) return;
        leaving = true;
        clearTimeout(autoTimer);
        splash.classList.add('fade-out');

        setTimeout(function () {
            window.location.href = 'main.html';
        }, FADE_DURATION_MS);
    }

    const autoTimer = setTimeout(enterSite, AUTO_DELAY_MS);

    document.addEventListener('click', enterSite, { once: true });
    document.addEventListener('touchstart', enterSite, { once: true });
    document.addEventListener('keydown', enterSite, { once: true });
}
