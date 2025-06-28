document.addEventListener('DOMContentLoaded', () => {
    const wrapper = document.querySelector('.wrapper');
    const loginLink = document.querySelector('.login-link');
    const registerLink = document.querySelector('.register-link');
    const btnPopup = document.querySelector('.btnLogin-popup');
    const welcomeMessage = document.querySelector(".welcome-message");
    const iconClose = document.querySelector('.icon-close');
    const registerForm = document.querySelector('.form-box.register form');

    // Initial setup
    if (registerLink) registerLink.addEventListener('click', () => wrapper.classList.add('active'));
    if (loginLink) loginLink.addEventListener('click', () => wrapper.classList.remove('active'));
    if (btnPopup) btnPopup.addEventListener('click', showLoginPopup);
    if (iconClose) iconClose.addEventListener('click', closePopup);

    // Password strength indicator
    document.getElementById('password')?.addEventListener('input', checkPasswordStrength);

    // Form submission handling
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegisterSubmit);
    }

    // Notification controls
    document.getElementById('close-notification')?.addEventListener('click', () => {
        document.getElementById('custom-notification').classList.remove('show');
    });

    function showLoginPopup() {
        wrapper.classList.add('active-popup');
        welcomeMessage.classList.add("welcome-hidden");
    }

    function closePopup() {
        wrapper.classList.remove('active-popup');
        welcomeMessage.classList.remove("welcome-hidden");
    }

    function checkPasswordStrength() {
        const password = document.getElementById('password').value;
        const strengthText = document.getElementById('password-strength-text');
        const strongPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        
        if (strongPassword.test(password)) {
            strengthText.textContent = "Strong Password";
            strengthText.style.color = "#00ff00";
        } else {
            strengthText.textContent = "Weak Password - Must contain 8+ chars with uppercase, lowercase, number, and special character";
            strengthText.style.color = "#ff0000";
        }
    }

    function handleRegisterSubmit(e) {
        e.preventDefault();
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm_password').value;
        const strongPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

        if (!strongPassword.test(password)) {
            showNotification('Password must contain at least 8 characters, one uppercase, one lowercase, one number, and one special character.');
            return;
        }

        if (password !== confirmPassword) {
            showNotification('Passwords do not match.');
            return;
        }

        // If validation passes, submit the form
        showNotification('Registration successful!', false);
        e.target.submit();
    }

    function showNotification(message, isError = true) {
        const notification = document.getElementById('custom-notification');
        const notificationMessage = document.getElementById('notification-message');
        notificationMessage.textContent = message;
        notification.style.backgroundColor = isError ? '#800000' : '#008000';
        notification.classList.add('show');
        setTimeout(() => notification.classList.remove('show'), 5000);
    }
});