const { invoke } = window.__TAURI__.core;

// Initialize the password manager
async function initPasswordManager() {
  try {
    console.log('Initializing password manager...');
    const hasMasterPassword = await invoke('has_master_password');
    console.log('Has master password:', hasMasterPassword);
    
    const setupForm = document.getElementById('setup-form');
    const loginForm = document.getElementById('login-form');
    const loginScreen = document.getElementById('login-screen');
    
    console.log('Setup form found:', !!setupForm);
    console.log('Login form found:', !!loginForm);
    
    // Make sure login screen is visible
    if (loginScreen) {
      loginScreen.style.display = 'flex';
    }
    
    if (hasMasterPassword) {
      if (setupForm) setupForm.style.display = 'none';
      if (loginForm) loginForm.style.display = 'block';
    } else {
      if (setupForm) setupForm.style.display = 'block';
      if (loginForm) loginForm.style.display = 'none';
    }
  } catch (err) {
    console.error('Failed to initialize password manager:', err);
  }
}

// Helper function to show error message
function showError(message, elementId = 'setup-error') {
  const errorElement = document.getElementById(elementId);
  if (errorElement) {
    errorElement.textContent = message;
    errorElement.style.display = 'block';
  }
}

// Helper function to clear error message
function clearError(elementId = 'setup-error') {
  const errorElement = document.getElementById(elementId);
  if (errorElement) {
    errorElement.textContent = '';
    errorElement.style.display = 'none';
  }
}

// Create master password
async function handleCreateMasterPassword() {
  console.log('handleCreateMasterPassword called');
  const newPassword = document.getElementById('new-master-password').value;
  const confirmPassword = document.getElementById('confirm-master-password').value;
  
  // Clear any previous error
  clearError();

  if (!newPassword || !confirmPassword) {
    showError('Please fill in both password fields');
    return;
  }

  if (newPassword !== confirmPassword) {
    showError('Passwords do not match');
    return;
  }

  try {
    console.log('Attempting to create master password...');
    await invoke('create_master_password', { password: newPassword });
    console.log('Master password created successfully');
    document.getElementById('setup-form').style.display = 'none';
    document.getElementById('login-form').style.display = 'block';
    alert('Master password created successfully!');
  } catch (err) {
    console.error('Error creating master password:', err);
    if (err.includes('Password too weak')) {
      showError(err.replace('Password too weak: ', ''));
    } else {
      showError('Failed to create master password: ' + err);
    }
  }
}

// Login handling
async function handleLogin() {
  console.log('handleLogin called');
  const password = document.getElementById('master-password').value;
  
  // Clear any previous error
  clearError('login-error');
  
  if (!password) {
    showError('Please enter your master password', 'login-error');
    return;
  }

  try {
    console.log('Attempting to verify master password...');
    await invoke('verify_master_password', { password });
    console.log('Master password verified successfully');
    
    // Hide login screen and show app
    const loginScreen = document.getElementById('login-screen');
    const app = document.getElementById('app');
    
    if (loginScreen && app) {
      loginScreen.style.display = 'none';
      app.style.display = 'block';
      console.log('Switched to app view');
    } else {
      console.error('Could not find login-screen or app elements');
    }
  } catch (err) {
    console.error('Login error:', err);
    if (err.includes('Invalid master password')) {
      showError('Invalid master password', 'login-error');
    } else {
      showError('Login failed: ' + err, 'login-error');
    }
  }
}

// Password visibility toggle
function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  if (input) {
    input.type = input.type === 'password' ? 'text' : 'password';
  }
}

// Copy to clipboard
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    const notification = document.createElement('div');
    notification.className = 'copy-notification';
    notification.textContent = 'Copied to clipboard';
    document.body.appendChild(notification);
    setTimeout(() => notification.remove(), 2000);
  } catch (err) {
    console.error('Failed to copy:', err);
    alert('Failed to copy to clipboard');
  }
}

async function addPassword() {
  const service = document.getElementById('service-input').value;
  const username = document.getElementById('username-input').value;
  const password = document.getElementById('password-input').value;

  if (!service || !username || !password) {
    alert('Please fill in all fields');
    return;
  }

  try {
    await invoke('add_password', { service, username, password });
    alert('Password saved successfully!');
    clearInputs();
  } catch (err) {
    if (err.includes('Password too weak')) {
      alert(err);
    } else {
      alert('Failed to save password: ' + err);
    }
  }
}

async function getPassword() {
  const service = document.getElementById('service-search').value;

  if (!service) {
    alert('Please enter a service name');
    return;
  }

  try {
    const entry = await invoke('get_password', { service });
    displayPasswordEntry(entry);
  } catch (err) {
    if (err.includes('not found')) {
      alert('No password found for this service');
    } else {
      alert('Failed to retrieve password: ' + err);
    }
    clearResults();
  }
}

function displayPasswordEntry(entry) {
  const resultDiv = document.getElementById('result');
  resultDiv.innerHTML = `
    <div class="password-entry">
      <p><strong>Service:</strong> ${entry.service}</p>
      <p><strong>Username:</strong> ${entry.username}</p>
      <p class="password-value">
        <strong>Password:</strong> 
        <span class="password-hidden" id="password-value">${entry.password}</span>
        <button class="toggle-password" onclick="togglePasswordVisibility('password-value')">
          <span class="eye-icon">👁️</span>
        </button>
        <button class="copy-button" onclick="copyToClipboard('${entry.password}')">
          Copy
        </button>
      </p>
    </div>
  `;
}

function clearInputs() {
  document.getElementById('service-input').value = '';
  document.getElementById('username-input').value = '';
  document.getElementById('password-input').value = '';
}

function clearResults() {
  const resultDiv = document.getElementById('result');
  if (resultDiv) {
    resultDiv.innerHTML = '';
  }
}

// Password generator functionality
function generatePassword(options) {
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  let chars = '';
  if (options.uppercase) chars += uppercase;
  if (options.lowercase) chars += lowercase;
  if (options.numbers) chars += numbers;
  if (options.symbols) chars += symbols;
  
  if (!chars) return '';
  
  let password = '';
  for (let i = 0; i < options.length; i++) {
    const randomIndex = Math.floor(Math.random() * chars.length);
    password += chars[randomIndex];
  }
  
  return password;
}

// Password list management
function displayPasswords(passwords) {
  const passwordsList = document.getElementById('passwords-list');
  passwordsList.innerHTML = '';
  
  passwords.forEach(entry => {
    const item = document.createElement('div');
    item.className = 'password-item';
    item.draggable = true;
    item.dataset.service = entry.service;
    
    item.innerHTML = `
      <div class="header">
        <span class="service">${entry.service}</span>
        <div class="actions">
          <button class="icon-button copy-username" title="Copy Username">👤</button>
          <button class="icon-button copy-password" title="Copy Password">🔑</button>
          <button class="icon-button delete-password" title="Delete">🗑️</button>
        </div>
      </div>
      <div class="details">
        <div>Username: ${entry.username}</div>
        <div>Password: ${'•'.repeat(10)}</div>
      </div>
    `;
    
    // Add event listeners for copy buttons
    item.querySelector('.copy-username').addEventListener('click', () => {
      copyToClipboard(entry.username);
    });
    
    item.querySelector('.copy-password').addEventListener('click', () => {
      copyToClipboard(entry.password);
    });
    
    item.querySelector('.delete-password').addEventListener('click', async () => {
      if (confirm('Are you sure you want to delete this password?')) {
        try {
          await invoke('delete_password', { service: entry.service });
          item.remove();
        } catch (err) {
          console.error('Failed to delete password:', err);
          alert('Failed to delete password');
        }
      }
    });
    
    // Drag and drop functionality
    item.addEventListener('dragstart', (e) => {
      e.dataTransfer.setData('text/plain', entry.service);
      item.classList.add('dragging');
    });
    
    item.addEventListener('dragend', () => {
      item.classList.remove('dragging');
    });
    
    passwordsList.appendChild(item);
  });
}

// Search functionality
function setupSearch() {
  const searchInput = document.getElementById('search-input');
  searchInput.addEventListener('input', async () => {
    const query = searchInput.value.toLowerCase();
    try {
      const allPasswords = await invoke('get_all_passwords');
      const filtered = allPasswords.filter(entry => 
        entry.service.toLowerCase().includes(query) ||
        entry.username.toLowerCase().includes(query)
      );
      displayPasswords(filtered);
    } catch (err) {
      console.error('Failed to search passwords:', err);
    }
  });
}

// Password generator UI
function setupPasswordGenerator() {
  const generateBtn = document.getElementById('generate-password');
  const generatorPanel = document.getElementById('password-generator');
  const generatePasswordBtn = document.getElementById('generate');
  
  generateBtn.addEventListener('click', () => {
    generatorPanel.style.display = generatorPanel.style.display === 'none' ? 'block' : 'none';
  });
  
  generatePasswordBtn.addEventListener('click', () => {
    const options = {
      uppercase: document.getElementById('include-uppercase').checked,
      lowercase: document.getElementById('include-lowercase').checked,
      numbers: document.getElementById('include-numbers').checked,
      symbols: document.getElementById('include-symbols').checked,
      length: parseInt(document.getElementById('password-length').value, 10)
    };
    
    const password = generatePassword(options);
    if (password) {
      document.getElementById('password-input').value = password;
      generatorPanel.style.display = 'none';
    }
  });
}

// Event listeners - only add them once when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM loaded, initializing app...');
  
  // Initialize the app
  initPasswordManager();
  setupPasswordGenerator();
  setupSearch();

  // Setup form
  const createPasswordBtn = document.getElementById('create-password-btn');
  console.log('Create password button found:', !!createPasswordBtn);
  
  if (createPasswordBtn) {
    console.log('Adding click listener to create password button');
    createPasswordBtn.addEventListener('click', (e) => {
      console.log('Create password button clicked');
      handleCreateMasterPassword();
    });
  } else {
    console.error('Create password button not found!');
  }

  const confirmMasterPassword = document.getElementById('confirm-master-password');
  if (confirmMasterPassword) {
    confirmMasterPassword.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') handleCreateMasterPassword();
    });
  }

  // Login form
  const loginBtn = document.getElementById('login-btn');
  if (loginBtn) {
    loginBtn.addEventListener('click', handleLogin);
  }

  const masterPassword = document.getElementById('master-password');
  if (masterPassword) {
    masterPassword.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') handleLogin();
    });
  }

  // Password visibility toggles
  document.querySelectorAll('.toggle-password').forEach(button => {
    button.addEventListener('click', () => {
      const targetId = button.dataset.target;
      togglePasswordVisibility(targetId);
    });
  });

  // Main app buttons
  const addBtn = document.getElementById('add-btn');
  if (addBtn) {
    addBtn.addEventListener('click', addPassword);
  }

  const getBtn = document.getElementById('get-btn');
  if (getBtn) {
    getBtn.addEventListener('click', getPassword);
  }

  // Load initial passwords
  invoke('get_all_passwords')
    .then(passwords => {
      displayPasswords(passwords);
    })
    .catch(err => {
      console.error('Failed to load passwords:', err);
    });
});
