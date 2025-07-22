window.addEventListener('DOMContentLoaded', () => {
    // Initialize Socket.IO client with explicit configuration
    const socket = io({
        autoConnect: false,
        withCredentials: true,
        // Use WebSocket transport first, fall back to polling if needed
        transports: ['websocket', 'polling'],
        // Important for Railway deployment
        path: '/socket.io/'
    });
        
    let currentUsername = null;
        
    // Debug logging for WebSocket connection
    socket.on('connect', () => {
        console.log('Connected to WebSocket server');
    });
        
    socket.on('disconnect', (reason) => {
        console.log('Disconnected:', reason);
    });

    socket.on('log_updated', () => {    
    console.log('[CLIENT] New logs available.');
    showInviteLogMsg('New invite log is available!', true);
    fetchAndRenderLogs();
    });

    socket.on('upload_complete', (summary) => {
    const msg = `Upload complete. ${summary.success} succeeded, ${summary.failed.length} failed.`;
    showToast(msg, summary.failed.length === 0 ? 'success' : 'error');
    
    if (summary.failed.length > 0) {
        console.warn('[CLIENT] Group creation failed for:', summary.failed);
        }
    });

    
    socket.on('connect_error', (error) => {
        console.error('Connection error:', error);
    });

    // --- DOM Elements ---
    const authContainer = document.getElementById('auth-container');
    const appContainer = document.getElementById('app-container');
    const loginView = document.getElementById('login-view');
    const registerView = document.getElementById('register-view');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const loginStatus = document.getElementById('login-status');
    const registerStatus = document.getElementById('register-status');
    const qrcodeDiv = document.getElementById('qrcode');
    const statusDiv = document.getElementById('status');
    const groupForm = document.getElementById('group-form');
    const logoutButton = document.getElementById('logout-button');
    const manualInputSection = document.getElementById('manual-input-section');
    const fileInputSection = document.getElementById('file-input-section');
    const manualNumbers = document.getElementById('manualNumbers');
    const groupNameInput = document.getElementById('groupName');
    const toggleLoginLink = document.getElementById('toggle-login'); // Added
    const toggleRegisterLink = document.getElementById('toggle-register'); // Added
    const contactsInput = document.getElementById('contacts');
    const logFileSelect = document.getElementById('log-file-select');
    const downloadLogButton = document.getElementById('download-invite-log-btn');
    const inviteLogMessage = document.getElementById('invite-log-message');

    // --- Status Message Handling ---
    function displayStatus(message, type = 'info') {
        statusDiv.textContent = message;
        statusDiv.className = `status ${type}`;  // Use CSS classes for styling
    }

    // Replace `populateLogFiles()` with this:
async function fetchAndRenderLogs() {
    const dropdown = document.getElementById('log-file-select'); // or 'logFileSelect'


    if (!dropdown) {
        console.warn('[fetchAndRenderLogs] Dropdown not found in DOM.');
        return;
    }

    try {
        const resp = await fetch('/list-logs');
        const logs = await resp.json();

        dropdown.innerHTML = '';

        if (!logs.length) {
            dropdown.innerHTML = '<option value="" disabled selected>No logs available</option>';
            return;
        }
logs.forEach((log) => {
    const opt = document.createElement('option');
    opt.value = log.filename;      // for download
    opt.textContent = log.display; // for display in dropdown
    dropdown.appendChild(opt);
});


    } catch (err) {
        console.error('[CLIENT] Failed to fetch log list:', err);
    }
}

    // --- UI Logic ---  (moved up)
    
    document.querySelectorAll('input[name="input-mode"]').forEach(radio => {
        radio.addEventListener('change', function() {
            if (this.value === 'manual') {
                manualInputSection.classList.remove('hidden');
                fileInputSection.classList.add('hidden');
                groupNameInput.required = true;
                contactsInput.required = false;
            } else {
                manualInputSection.classList.add('hidden');
                fileInputSection.classList.remove('hidden');
                groupNameInput.required = false;
                contactsInput.required = true;
            }
        });
        });
    
    function toggleAuthView() {
            const loginView = document.getElementById('login-view');
            const registerView = document.getElementById('register-view');
    
            loginView.classList.toggle('hidden');
            registerView.classList.toggle('hidden');
        }

        function showApp(username) {
            // Clean up any existing state
            qrcodeDiv.innerHTML = '';
            displayStatus('Initializing session... Please wait.', 'info');
            
            // Disconnect any existing socket connection
            if (socket.connected) {
                socket.disconnect();
            }
            
            // Clear any existing event listeners to prevent duplicates
            socket.off('qr');
            socket.off('authenticated');
            socket.off('ready');
            socket.off('disconnected');
            socket.off('auth_failure');
            
            // Set up new connection
            currentUsername = username;
            socket.auth = { username };
            
            // Connect to the server
            socket.connect();
            
            // Update UI
            authContainer.classList.add('hidden');
            appContainer.classList.remove('hidden');
            
            // Set up event listeners
            setupSocketListeners();

            // Fetch and populate log files
            fetchAndRenderLogs();
        }

        function showLogin() {
            currentUsername = null;
            authContainer.classList.remove('hidden');
            appContainer.classList.add('hidden');
            socket.disconnect();

            // Clear form fields for privacy and usability
            loginForm.reset();
            registerForm.reset();
            loginStatus.textContent = '';
            registerStatus.textContent = '';

            // Reset app state as well to prevent flash of old content
            qrcodeDiv.innerHTML = '';
            statusDiv.textContent = 'Connecting to WhatsApp...';
        }

        // --- Group Form Event Listener ---
        groupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const mode = document.querySelector('input[name="input-mode"]:checked').value;
            const submitButton = groupForm.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.textContent = 'Creating...';

            try {
                if (mode === 'manual') {
                    const groupName = document.getElementById('groupName').value;
                    const numbers = document.getElementById('manualNumbers').value;
                    const desiredAdminNumber = document.getElementById('desiredAdminNumber').value;

                    const response = await fetch('/create-group', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ groupName, numbers, desiredAdminNumber }),
                    });

                    const result = await response.json();
                    displayStatus(result.message || (response.ok ? 'Group creation initiated.' : 'Error creating group.'), response.ok ? 'success' : 'error');

                } else { // CSV mode
                    const formData = new FormData();
                    const contactsFile = document.getElementById('contacts').files[0];
                    if (!contactsFile) {
                        displayStatus('Please select a CSV file.', 'error');
                        return
                    }
                    formData.append('contacts', contactsFile);

                    const response = await fetch('/upload', {
                        method: 'POST',
                        body: formData,
                    });

                    const result = await response.json();
                    displayStatus(result.message || (response.ok ? 'CSV processing started.' : 'Error uploading file.'), response.ok ? 'success' : 'error');
                }
            } catch (error) {
                console.error('Form submission error:', error);
                displayStatus('An error occurred. Please try again.', 'error');
            } finally {
                submitButton.disabled = false;
                submitButton.textContent = 'Create Group';
                groupForm.reset(); // Reset form fields after submission
                // Ensure manual is the default view after reset
                document.querySelector('input[value="manual"]').dispatchEvent(new Event('change'));
            }
        });

        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    credentials: 'include', // Important for cookies
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json().catch(() => ({}));
                if (response.ok) {
                    // Poll /check-auth until it returns success (max 5 tries)
                    let authenticated = false;
                    for (let i = 0; i < 5; i++) {
                        const check = await fetch('/check-auth', { credentials: 'include' });
                        if (check.ok) {
                            authenticated = true;
                            break;
                        }
                        await new Promise(resolve => setTimeout(resolve, 300));
                    }
                    if (!authenticated) throw new Error('Session not established after login');

                    // Wait a bit more to ensure cookie propagation
                    await new Promise(resolve => setTimeout(resolve, 500));

                    socket.auth = { username };
                    socket.connect();

                    // Wait for connection or retry once if it fails
                    let connected = false;
                    for (let i = 0; i < 2; i++) {
                        await new Promise(resolve => setTimeout(resolve, 400));
                        if (socket.connected) {
                            connected = true;
                            break;
                        }
                        if (!connected && i === 0) {
                            // Retry once
                            socket.connect();
                        }
                    }
                    if (connected) {
                        showApp(username);
                    } else {
                        throw new Error('Failed to establish WebSocket connection');
                    }
                    fetchAndRenderLogs();
                } else {
                    loginStatus.textContent = data.error || 'Login failed.';
                    loginStatus.className = 'auth-status error'; // Consistent error class
                }

            } catch (error) {
                console.error('Login error:', error);
                loginStatus.textContent = 'Error connecting to server: ' + error.message;; // Consistent error display
                loginStatus.className = 'auth-status error';
            }
        });

        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('register-username').value;
            const password = document.getElementById('register-password').value;

            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    credentials: 'include', // Important for cookies
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password })
                });

                const data = await response.json().catch(() => ({}));
                if (response.ok) {
                    // Only show the app after registration is confirmed
                    showApp(username);
                    fetchAndRenderLogs();
                } else {
                    registerStatus.textContent = data.error || data.message || 'Registration failed.';
                    registerStatus.className = 'auth-status error';
                }
            } catch (error) {
                console.error('Registration error:', error);
                registerStatus.textContent = 'Error connecting to server: ' + error.message;
                registerStatus.className = 'auth-status error';
            }
        });

        logoutButton.addEventListener('click', async () => {
            try {
                const response = await fetch('/logout', { 
                    method: 'POST',
                    credentials: 'include'
                });
                if (response.ok) {
                    // Disconnect socket and clean up
                    socket.disconnect();
                    socket.off(); // Remove all event listeners

                    // Wait for socket to fully disconnect before showing login
                    await new Promise(resolve => {
                        if (!socket.connected) return resolve();
                        socket.once('disconnect', resolve);
                    });

                    // Reset UI
                    showLogin();

                    // Force a small delay before allowing re-login
                    await new Promise(resolve => setTimeout(resolve, 500));
                } else {
                    const data = await response.json().catch(() => ({}));
                    displayStatus(data.error || 'Logout failed.', 'error');
                }
            } catch (error) {
                displayStatus('Error during logout: ' + error.message, 'error');
                //statusDiv.className = 'status error'; // Remove direct class manipulation
            }
        });

        // Set up socket event listeners
        function setupSocketListeners() {
            // Remove any existing listeners first to prevent duplicates
            socket.off('qr');
            socket.off('status');
            socket.off('error');

            // QR Code Handler
            socket.on('qr', (qr) => {
                // Clear any previous error states
                statusDiv.className = 'status';
                displayStatus('Scan this QR code with your WhatsApp to continue.', 'info');
                
                // Clear the QR code div and create a new canvas
                qrcodeDiv.innerHTML = '';
                const canvas = document.createElement('canvas');
                
                // Generate QR code with error handling
                QRCode.toCanvas(canvas, qr, { 
                    width: 256,
                    margin: 2,
                    color: {
                        dark: '#000000',
                        light: '#ffffff'
                    }
                }, (err) => {
                    if (err) {
                        console.error('Error generating QR code:', err);
                        displayStatus('Error generating QR code. Please try again.', 'error');
                        return;
                    }
                    qrcodeDiv.appendChild(canvas);
                });
            });

            // Status Message Handler
            socket.on('status', (message) => {
                // Map technical errors to user-friendly messages
                let userMessage = message;
                if (message.includes('Could not start WhatsApp session')) {
                    userMessage = 'We could not start your WhatsApp session. Please try again in a few seconds.';
                } else if (message.includes('Authentication failed')) {
                    userMessage = 'Authentication failed. Please try again.';
                } else if (message.includes('Client disconnected')) {
                    userMessage = 'Your WhatsApp session was disconnected. Please refresh and log in again.';
                } else if (message.includes('Error') || message.includes('error') || message.includes('fail') || message.includes('Fail')) {
                    userMessage = 'An error occurred. Please try again.'; // More user-friendly error
                }
                statusDiv.textContent = userMessage;
                // Set appropriate status class based on message content
                if (userMessage.includes('error') || userMessage.includes('Error') || 
                    userMessage.includes('fail') || userMessage.includes('Fail') ||
                    userMessage.includes('disconnected') || userMessage.includes('could not')) {
                    statusDiv.className = 'status error';
                } else if (userMessage.includes('ready')) {
                    displayStatus('Client is ready!', 'success');
                    qrcodeDiv.innerHTML = `
                        <div class="status-container">
                            <svg width="80" height="80" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <circle cx="12" cy="12" r="10" fill="#4CAF50"></circle>
                                <path d="M8 12.3l2.7 2.7L16 9" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
                            </svg>
                            <h3>Client Ready</h3>
                            <p>You can now create groups.</p>
                        </div>`;
                } else {
                    displayStatus(userMessage, 'info')
                }
            });
            
            // Error Handler
            socket.on('error', (error) => {
                console.error('Socket error:', error);
                statusDiv.className = 'status error';
                displayStatus('Connection error. Please refresh the page and try again.', 'error');
            });
        }
        
        // Initialize socket listeners on page load
        setupSocketListeners();

        // Check login status on page load
        (async function() {
            const response = await fetch('/check-auth');
            if (response.ok) {
                const { user } = await response.json();
                showApp(user.username);
            } else {
                showLogin();
            }
        })();
        function showInviteLogMsg(msg, success=true) {
            const msgDiv = document.getElementById('invite-log-message');
            msgDiv.textContent = msg;
            msgDiv.style.color = success ? '#219150' : '#d32f2f';
        }

// Download invite log handler
document.getElementById('download-invite-log-btn').addEventListener('click', function () {
    const selectedLogFile = logFileSelect.value;

    if (!selectedLogFile) {
        showInviteLogMsg('Please select a log file to download.', false);
        return;
    }

    fetch(`/download/invite-log/${selectedLogFile}`)
        .then(response => {
            if (response.ok) return response.blob();
            else return response.json().then(x => {throw new Error(x.error || "Download failed");});
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const tempLink = document.createElement('a');
            tempLink.href = url;
            tempLink.download = `group-invite-log.csv`;
            document.body.appendChild(tempLink);
            tempLink.click();
            document.body.removeChild(tempLink);
            window.URL.revokeObjectURL(url);
            showInviteLogMsg('Downloaded invite log successfully!');
        })
        .catch(err => {
            showInviteLogMsg('No invite log available yet. Try again later. (' + err.message + ')', false);
        });
    });

    // Attach event listener for toggling auth view
    if (toggleRegisterLink)
        toggleRegisterLink.addEventListener('click', toggleAuthView);

    // Attach event listener for toggling auth view
    if (toggleLoginLink)
        toggleLoginLink.addEventListener('click', toggleAuthView);
});